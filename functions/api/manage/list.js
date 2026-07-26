import {
    readIndex, mergeOperationsToIndex, deleteAllOperations, rebuildIndex,
    getIndexInfo, getIndexStorageStats
} from '../../utils/indexManager.js';
import { getDatabase } from '../../utils/databaseAdapter.js';
import { createMetadataViewContext, serializeFileRecordForManagement } from '../../utils/metadata/metadataView.js';
import { validateSession } from '../../utils/auth/sessionManager.js';
import { getUser } from '../../utils/auth/userManager.js';

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

export async function onRequest(context) {
    const { request, waitUntil, env } = context;
    const url = new URL(request.url);

    // 子账号目录访问控制：直接从 session 重新加载用户信息，不依赖中间件注入
    let currentUser = context.currentUser;
    let isSubAccount = false;

    // 如果中间件没有正确注入 currentUser，则直接从 session 加载
    if (!currentUser) {
        const userSession = await validateSession(env, request, 'user');
        if (userSession.valid && userSession.session?.username) {
            const db = getDatabase(env);
            currentUser = await getUser(db, userSession.session.username);
            if (currentUser) {
                isSubAccount = true;
            }
        }
    } else {
        isSubAccount = currentUser && context.authType === 'user';
    }

    if (isSubAccount && currentUser) {
        const allowedDirs = Array.isArray(currentUser.allowedDirs) ? currentUser.allowedDirs : [];
        // 检查是否有完整访问权限（allowedDirs 包含 '/' 或空数组）
        const hasFullAccess = allowedDirs.length === 0 || allowedDirs.includes('/');
        
        if (!hasFullAccess) {
            // 子账号受限：后续会根据 dir 参数做进一步过滤
            // 如果 allowedDirs 为空数组，无权访问任何目录
            if (allowedDirs.length === 0) {
                return new Response(JSON.stringify({
                    files: [],
                    directories: [],
                    totalCount: 0,
                    directFileCount: 0,
                    directFolderCount: 0,
                    returnedCount: 0,
                    restricted: true,
                    message: '您没有访问任何目录的权限'
                }), {
                    headers: { "Content-Type": "application/json", ...corsHeaders }
                });
            }
        }
    }

    // 解析查询参数
    let start = parseInt(url.searchParams.get('start'), 10) || 0;
    let count = parseInt(url.searchParams.get('count'), 10) || 50;
    let sum = url.searchParams.get('sum') === 'true';
    let recursive = url.searchParams.get('recursive') === 'true';
    let dir = url.searchParams.get('dir') || '';
    let search = url.searchParams.get('search') || '';
    let channel = url.searchParams.get('channel') || '';
    let listType = url.searchParams.get('listType') || '';
    let accessStatus = url.searchParams.get('accessStatus') || '';
    let action = url.searchParams.get('action') || '';
    let includeTags = url.searchParams.get('includeTags') || '';
    let excludeTags = url.searchParams.get('excludeTags') || '';
    let label = url.searchParams.get('label') || '';
    let fileType = url.searchParams.get('fileType') || '';
    let channelName = url.searchParams.get('channelName') || '';
    
    // 网盘增强搜索参数
    let minSize = url.searchParams.get('minSize');
    let maxSize = url.searchParams.get('maxSize');
    let startDate = url.searchParams.get('startDate');
    let endDate = url.searchParams.get('endDate');
    let sortBy = url.searchParams.get('sortBy') || '';
    let sortOrder = url.searchParams.get('sortOrder') || 'desc';

    // 转换参数类型
    minSize = minSize ? parseInt(minSize, 10) : null;
    maxSize = maxSize ? parseInt(maxSize, 10) : null;
    startDate = startDate ? parseInt(startDate, 10) : null;
    endDate = endDate ? parseInt(endDate, 10) : null;
    sortBy = ['name', 'size', 'time'].includes(sortBy) ? sortBy : null;
    sortOrder = sortOrder === 'asc' ? 'asc' : 'desc';

    // 处理搜索关键字
    if (search) {
        search = decodeURIComponent(search).trim();
    }

    // 处理标签参数
    const includeTagsArray = includeTags ? includeTags.split(',').map(t => t.trim()).filter(t => t) : [];
    const excludeTagsArray = excludeTags ? excludeTags.split(',').map(t => t.trim()).filter(t => t) : [];

    // 处理筛选参数（支持逗号分隔的多选）
    const listTypeArray = listType ? listType.split(',').map(t => t.trim()).filter(t => t) : [];
    const accessStatusArray = accessStatus ? accessStatus.split(',').map(t => t.trim()).filter(t => t) : [];
    const labelArray = label ? label.split(',').map(t => t.trim()).filter(t => t) : [];
    const fileTypeArray = fileType ? fileType.split(',').map(t => t.trim()).filter(t => t) : [];
    const channelArray = channel ? channel.split(',').map(t => t.trim()).filter(t => t) : [];
    const channelNameArray = channelName ? channelName.split(',').map(t => t.trim()).filter(t => t) : [];

    // 处理目录参数
    if (dir) {
        // 路径安全处理：防止路径穿越
        dir = dir.replace(/\.\./g, '_').replace(/\\/g, '/').replace(/\/{2,}/g, '/');
    }
    if (dir.startsWith('/')) {
        dir = dir.substring(1);
    }
    if (dir && !dir.endsWith('/')) {
        dir += '/';
    }

    // 子账号目录强制过滤：确保请求目录在 allowedDirs 范围内
    if (isSubAccount && currentUser) {
        const allowedDirs = Array.isArray(currentUser.allowedDirs) ? currentUser.allowedDirs : [];
        const hasFullAccess = allowedDirs.length === 0 || allowedDirs.includes('/');
        
        if (!hasFullAccess && allowedDirs.length > 0) {
            // 根目录请求放行（后续过滤逻辑会只显示允许的目录入口）
            // 只拦截明确不在范围内的子目录请求
            if (dir !== '') {
                const isAllowed = allowedDirs.some(allowed => {
                    const normAllowed = allowed.replace(/^\/+|\/+$/g, '');
                    if (normAllowed === '') return true;
                    return dir.startsWith(normAllowed + '/');
                });
                if (!isAllowed) {
                    return new Response(JSON.stringify({
                        files: [],
                        directories: [],
                        totalCount: 0,
                        directFileCount: 0,
                        directFolderCount: 0,
                        returnedCount: 0,
                        restricted: true,
                        message: '您没有访问该目录的权限'
                    }), {
                        headers: { "Content-Type": "application/json", ...corsHeaders }
                    });
                }
            }
        }
    }

    try {
        // 特殊操作：重建索引
        if (action === 'rebuild') {
            waitUntil(rebuildIndex(context, (processed) => {
                console.log(`Rebuilt ${processed} files...`);
            }));

            return new Response('Index rebuilt asynchronously', {
                headers: { "Content-Type": "text/plain", ...corsHeaders }
            });
        }

        // 特殊操作：合并挂起的原子操作到索引
        if (action === 'merge-operations') {
            waitUntil(mergeOperationsToIndex(context));

            return new Response('Operations merged into index asynchronously', {
                headers: { "Content-Type": "text/plain", ...corsHeaders }
            });
        }

        // 特殊操作：清除所有原子操作
        if (action === 'delete-operations') {
            waitUntil(deleteAllOperations(context));

            return new Response('All operations deleted asynchronously', {
                headers: { "Content-Type": "text/plain", ...corsHeaders }
            });
        }

        // 特殊操作：获取索引存储信息
        if (action === 'index-storage-stats') {
            const stats = await getIndexStorageStats(context);
            return new Response(JSON.stringify(stats), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        // 特殊操作：获取索引信息
        if (action === 'info') {
            const info = await getIndexInfo(context, {
                timezoneOffset: url.searchParams.get('timezoneOffset'),
                maxPoints: url.searchParams.get('trendMaxPoints'),
                seriesLimit: url.searchParams.get('trendSeriesLimit'),
                startDate: url.searchParams.get('trendStartDate'),
                endDate: url.searchParams.get('trendEndDate')
            });
            return new Response(JSON.stringify(info), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        // 普通查询：只返回总数
        if (count === -1 && sum) {
            const result = await readIndex(context, {
                search,
                directory: dir,
                channel: channelArray,
                listType: listTypeArray,
                accessStatus: accessStatusArray,
                label: labelArray,
                fileType: fileTypeArray,
                channelName: channelNameArray,
                includeTags: includeTagsArray,
                excludeTags: excludeTagsArray,
                countOnly: true,
                minSize,
                maxSize,
                startDate,
                endDate
            });

            return new Response(JSON.stringify({
                sum: result.totalCount,
                indexLastUpdated: result.indexLastUpdated
            }), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        // 普通查询：返回数据
        const result = await readIndex(context, {
            search,
            directory: dir,
            start,
            count,
            channel: channelArray,
            listType: listTypeArray,
            accessStatus: accessStatusArray,
            label: labelArray,
            fileType: fileTypeArray,
            channelName: channelNameArray,
            includeTags: includeTagsArray,
            excludeTags: excludeTagsArray,
            includeSubdirFiles: recursive,
            minSize,
            maxSize,
            startDate,
            endDate,
            sortBy,
            sortOrder
        });

        // 索引读取失败，直接从 KV 中获取所有文件记录
        if (!result.success) {
            const dbRecords = await getAllFileRecords(context.env, dir);

            // 子账号：在 KV fallback 路径也需要过滤
            let filteredDbDirs = dbRecords.directories;
            let filteredDbFiles = dbRecords.files;
            if (isSubAccount && currentUser) {
                const allowedDirs = Array.isArray(currentUser.allowedDirs) ? currentUser.allowedDirs : [];
                const hasFullAccess = allowedDirs.length === 0 || allowedDirs.includes('/');
                if (!hasFullAccess) {
                    const normalizedAllowed = allowedDirs.map(d => d.replace(/^\/+|\/+$/g, ''));
                    // 根目录下：只显示允许的目录，隐藏散落文件
                    if (dir === '') {
                        filteredDbDirs = dbRecords.directories.filter(d => {
                            return normalizedAllowed.some(allowed => d === allowed || d.startsWith(allowed + '/'));
                        });
                        filteredDbFiles = []; // 根目录不允许散落文件
                    }
                }
            }

            return new Response(JSON.stringify({
                files: filteredDbFiles,
                directories: filteredDbDirs,
                totalCount: filteredDbFiles.length + filteredDbDirs.length,
                directFileCount: filteredDbFiles.length,
                directFolderCount: filteredDbDirs.length,
                returnedCount: filteredDbFiles.length + filteredDbDirs.length,
                indexLastUpdated: Date.now(),
                isIndexedResponse: false // 标记这是来自 KV 的响应
            }), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        const db = getDatabase(context.env);
        const metadataViewContext = await createMetadataViewContext(db, context.env);

        // 转换文件格式
        const compatibleFiles = await Promise.all(
            result.files.map(file => serializeFileRecordForManagement(db, context.env, file, metadataViewContext))
        );

        // 子账号：过滤掉不在 allowedDirs 范围内的目录和文件
        let filteredDirectories = result.directories;
        let filteredFiles = compatibleFiles;
        if (isSubAccount && currentUser) {
            const allowedDirs = Array.isArray(currentUser.allowedDirs) ? currentUser.allowedDirs : [];
            const hasFullAccess = allowedDirs.length === 0 || allowedDirs.includes('/');
            if (!hasFullAccess) {
                const normalizedAllowed = allowedDirs.map(d => d.replace(/^\/+|\/+$/g, ''));
                // 根目录下：只显示允许的目录，隐藏散落文件
                if (dir === '') {
                    filteredDirectories = result.directories.filter(d => {
                        return normalizedAllowed.some(allowed => d === allowed || d.startsWith(allowed + '/'));
                    });
                    filteredFiles = []; // 根目录不允许显示散落文件
                }
            }
        }

        return new Response(JSON.stringify({
            files: filteredFiles,
            directories: filteredDirectories,
            totalCount: result.totalCount,
            directFileCount: result.directFileCount,
            directFolderCount: result.directFolderCount,
            returnedCount: result.returnedCount,
            indexLastUpdated: result.indexLastUpdated,
            isIndexedResponse: true // 标记这是来自索引的响应
        }), {
            headers: { "Content-Type": "application/json", ...corsHeaders }
        });

    } catch (error) {
        console.error('Error in list-indexed API:', error);
        return new Response(JSON.stringify({
            error: 'Internal server error',
            message: error.message
        }), {
            status: 500,
            headers: { "Content-Type": "application/json", ...corsHeaders }
        });
    }
}

async function getAllFileRecords(env, dir) {
    const allRecords = [];
    let cursor = null;

    try {
        const db = getDatabase(env);
        const metadataViewContext = await createMetadataViewContext(db, env);

        while (true) {
            const response = await db.list({
                prefix: dir,
                limit: 1000,
                cursor: cursor
            });

            // 检查响应格式
            if (!response || !response.keys || !Array.isArray(response.keys)) {
                console.error('Invalid response from database list:', response);
                break;
            }

            cursor = response.cursor;

            for (const item of response.keys) {
                // 跳过管理相关的键和回收站、上传会话等系统键
                if (item.name.startsWith('manage@') || item.name.startsWith('chunk_') ||
                    item.name.startsWith('trash_') || item.name.startsWith('upload_session_') ||
                    item.name.startsWith('op_') || item.name.startsWith('index_')) {
                    continue;
                }

                // 跳过没有元数据的文件
                if (!item.metadata || !item.metadata.TimeStamp) {
                    continue;
                }

                allRecords.push(await serializeFileRecordForManagement(db, env, item, metadataViewContext));
            }

            if (!cursor) break;

            // 添加协作点
            await new Promise(resolve => setTimeout(resolve, 10));
        }

        // 提取目录信息
        const directories = new Set();
        const filteredRecords = [];
        allRecords.forEach(item => {
            const subDir = item.name.substring(dir.length);
            const firstSlashIndex = subDir.indexOf('/');
            if (firstSlashIndex !== -1) {
                directories.add(dir + subDir.substring(0, firstSlashIndex));
            } else {
                filteredRecords.push(item);
            }
        });

        return {
            files: filteredRecords,
            directories: Array.from(directories),
            totalCount: allRecords.length,
            directFileCount: filteredRecords.length,
            directFolderCount: directories.size,
            returnedCount: filteredRecords.length
        };

    } catch (error) {
        console.error('Error in getAllFileRecords:', error);
        return {
            files: [],
            directories: [],
            totalCount: 0,
            directFileCount: 0,
            directFolderCount: 0,
            returnedCount: 0,
            error: error.message
        };
    }
}
