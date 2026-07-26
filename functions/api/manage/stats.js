// 统计概览 API
// GET /api/manage/stats?action=overview

import { getDatabase } from '../../utils/databaseAdapter.js';
import { getIndexInfo, readIndex } from '../../utils/indexManager.js';
import { listUsers, getLogs } from '../../utils/auth/userManager.js';

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const action = url.searchParams.get('action') || 'overview';

    if (action !== 'overview') {
        return jsonRes({ error: 'Unsupported action. Use action=overview' }, 400);
    }

    try {
        const db = getDatabase(env);

        // 并行获取各维度数据
        const [indexInfo, usersResult, logsResult] = await Promise.all([
            getIndexInfo(context),
            listUsers(db),
            getLogs(db, { limit: 5 }),
        ]);

        const totalFiles = indexInfo?.totalFiles || 0;
        let totalSize = 0; // 从索引中计算
        const storageByType = {};
        let starredCount = 0;
        let trashCount = 0;

        // 读取索引以获取详细统计
        let indexResult;
        try {
            indexResult = await readIndex(context, { count: 99999 });
        } catch (e) {
            indexResult = { success: false, files: [] };
        }

        if (indexResult.success && indexResult.files) {
            for (const file of indexResult.files) {
                const meta = file.metadata || {};

                // 统计总大小
                totalSize += (meta.FileSize || 0);

                // 统计星标数
                if (meta.Starred === true) {
                    starredCount++;
                }

                // 统计回收站文件（Trash 标记）
                if (meta.Trash === true) {
                    trashCount++;
                }

                // 按类型分类统计大小
                const fileType = categorizeFileType(meta.FileType || '', meta.FileName || '');
                if (!storageByType[fileType]) {
                    storageByType[fileType] = 0;
                }
                storageByType[fileType] += (meta.FileSize || 0);
            }
        }

        // 获取活跃分享数
        let activeShares = 0;
        try {
            const shareResult = await db.list({ prefix: 'manage@share@' });
            if (shareResult.keys) {
                activeShares = shareResult.keys.length;
            }
        } catch (e) {
            // 忽略分享计数错误
        }

        // 格式化存储大小
        const formattedTotalSize = formatSize(totalSize);
        const formattedStorageByType = {};
        for (const [type, size] of Object.entries(storageByType)) {
            formattedStorageByType[type] = formatSize(size);
        }

        return jsonRes({
            totalFiles,
            totalSize: formattedTotalSize,
            starredFiles: starredCount,
            activeShares,
            trashFiles: trashCount,
            users: (usersResult.users || []).length,
            recentLogs: logsResult.logs || [],
            storageByType: formattedStorageByType,
        });
    } catch (error) {
        console.error('Error in stats API:', error);
        return jsonRes({ error: error.message || 'Internal server error' }, 500);
    }
}

/**
 * 根据文件 MIME 类型或扩展名分类
 */
function categorizeFileType(mimeType, fileName) {
    if (!mimeType && !fileName) return 'other';

    const mime = (mimeType || '').toLowerCase();
    const ext = fileName.split('.').pop().toLowerCase();

    if (mime.startsWith('image/') || ['jpg','jpeg','png','gif','webp','bmp','svg','ico','tiff'].includes(ext)) {
        return 'image';
    }
    if (mime.startsWith('video/') || ['mp4','webm','avi','mov','mkv','flv'].includes(ext)) {
        return 'video';
    }
    if (mime.startsWith('audio/') || ['mp3','wav','ogg','flac','aac','m4a'].includes(ext)) {
        return 'audio';
    }
    if (mime === 'application/pdf' || ext === 'pdf') {
        return 'document';
    }
    if (mime.startsWith('text/') || ['txt','md','json','xml','csv','html','css','js','ts'].includes(ext)) {
        return 'text';
    }
    if (mime.startsWith('application/zip') || ['zip','rar','7z','tar','gz','bz2'].includes(ext)) {
        return 'archive';
    }

    return 'other';
}

/**
 * 格式化文件大小为人类可读格式
 */
function formatSize(bytes) {
    if (bytes === 0) return '0B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const size = (bytes / Math.pow(k, i)).toFixed(1);
    return size + units[i];
}

/**
 * 构建标准 JSON 响应
 */
function jsonRes(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
        },
    });
}
