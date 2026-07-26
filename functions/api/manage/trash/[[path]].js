// 回收站管理 API
// 支持: 列出回收站文件、从回收站恢复文件、彻底删除回收站文件
import { deleteFile } from '../delete/[[path]].js';
import { getDatabase, checkDatabaseConfig } from '../../../utils/databaseAdapter.js';
import { addFileToIndex, removeFileFromIndex } from '../../../utils/indexManager.js';
import { cleanPersistedMetadata } from '../../../utils/metadata/metadataSecurity.js';

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

// 回收站键前缀
const TRASH_PREFIX = 'trash_';

export async function onRequest(context) {
    const { request, env, params, waitUntil } = context;

    // OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: corsHeaders,
        });
    }

    const url = new URL(request.url);

    // 检查数据库配置
    const dbConfig = checkDatabaseConfig(env);
    if (!dbConfig.configured) {
        return new Response(JSON.stringify({
            success: false,
            message: 'Database not configured.',
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }

    const db = getDatabase(env);

    // 解析路径参数（encodedFileId）
    const rawPath = params.path ? decodeURIComponent(params.path) : '';
    const fileId = rawPath ? rawPath.split(',').join('/') : '';

    // GET (无 path 参数): 列出回收站所有文件
    if (request.method === 'GET') {
        return await listTrash(db);
    }

    // POST /{encodedFileId}: 从回收站恢复文件
    if (request.method === 'POST') {
        return await restoreFromTrash(context, db, fileId, url, waitUntil);
    }

    // DELETE /{encodedFileId}: 彻底删除
    if (request.method === 'DELETE') {
        return await permanentlyDelete(context, db, fileId, url, waitUntil);
    }

    return new Response(JSON.stringify({
        success: false,
        message: 'Method not allowed.',
    }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
}

// 列出回收站所有文件
async function listTrash(db) {
    try {
        const trashFiles = [];
        let cursor = null;

        // 遍历 KV，分页获取所有 trash_ 前缀的记录
        while (true) {
            const listOptions = { prefix: TRASH_PREFIX, limit: 1000 };
            if (cursor) {
                listOptions.cursor = cursor;
            }

            const listResponse = await db.list(listOptions);

            // 检查响应格式
            if (!listResponse || !listResponse.keys || !Array.isArray(listResponse.keys)) {
                console.error('Invalid response from database list:', listResponse);
                break;
            }

            for (const item of listResponse.keys) {
                const trashKey = item.name;
                const originalFileId = trashKey.slice(TRASH_PREFIX.length);

                // 优先使用 list 返回的内联 metadata，缺失时回退到 getWithMetadata
                let recordMetadata = item.metadata;

                if (!recordMetadata) {
                    const record = await db.getWithMetadata(trashKey);
                    if (!record || !record.metadata) {
                        continue;
                    }
                    recordMetadata = record.metadata;
                }

                trashFiles.push({
                    fileId: originalFileId,
                    trashKey: trashKey,
                    trashTime: recordMetadata.trashTime || null,
                    originalPath: recordMetadata.originalPath || originalFileId,
                    metadata: recordMetadata,
                });
            }

            cursor = listResponse.cursor;
            if (!cursor) break;
        }

        // 按删除时间倒序
        trashFiles.sort((a, b) => (b.trashTime || 0) - (a.trashTime || 0));

        return new Response(JSON.stringify({
            success: true,
            files: trashFiles,
            total: trashFiles.length,
        }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    } catch (error) {
        console.error('List trash failed:', error);
        return new Response(JSON.stringify({
            success: false,
            error: error.message,
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
}

// 从回收站恢复文件
async function restoreFromTrash(context, db, fileId, url, waitUntil) {
    try {
        if (!fileId) {
            return new Response(JSON.stringify({
                success: false,
                message: 'File ID is required.',
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        const trashKey = `${TRASH_PREFIX}${fileId}`;
        const record = await db.getWithMetadata(trashKey);

        if (!record || !record.metadata) {
            return new Response(JSON.stringify({
                success: false,
                message: 'Trash record not found.',
            }), {
                status: 404,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 检查原位置是否已被占用（避免恢复时覆盖）
        const existing = await db.getWithMetadata(fileId);
        if (existing && existing.value !== null) {
            return new Response(JSON.stringify({
                success: false,
                message: '原路径已存在文件，恢复将导致覆盖，请先处理该文件。',
            }), {
                status: 409,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 清理回收站专用元数据字段
        const metadata = { ...record.metadata };
        delete metadata.trashTime;
        delete metadata.originalPath;
        const cleanedMetadata = cleanPersistedMetadata(metadata);

        // 将 trash_{fileId} 的元数据移回 {fileId}
        await db.put(fileId, record.value, { metadata: cleanedMetadata });
        await db.delete(trashKey);

        // 更新索引：添加恢复的文件
        waitUntil(addFileToIndex(context, fileId, cleanedMetadata));

        return new Response(JSON.stringify({
            success: true,
            fileId,
        }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    } catch (error) {
        console.error('Restore from trash failed:', error);
        return new Response(JSON.stringify({
            success: false,
            error: error.message,
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
}

// 彻底删除回收站文件
async function permanentlyDelete(context, db, fileId, url, waitUntil) {
    try {
        if (!fileId) {
            return new Response(JSON.stringify({
                success: false,
                message: 'File ID is required.',
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        const { env } = context;
        const trashKey = `${TRASH_PREFIX}${fileId}`;
        const record = await db.getWithMetadata(trashKey);

        if (!record || !record.metadata) {
            return new Response(JSON.stringify({
                success: false,
                message: 'Trash record not found.',
            }), {
                status: 404,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 清理回收站专用字段后，临时写回原位置，以便复用 deleteFile 从存储后端删除
        const metadata = { ...record.metadata };
        delete metadata.trashTime;
        delete metadata.originalPath;
        const cleanedMetadata = cleanPersistedMetadata(metadata);

        await db.put(fileId, record.value, { metadata: cleanedMetadata });

        // 调用 deleteFile 函数从存储后端（R2/S3/WebDAV/Telegram 等）删除实际文件数据
        const cdnUrl = `https://${url.hostname}/file/${fileId}`;
        const success = await deleteFile(env, fileId, cdnUrl, url);
        if (!success) {
            throw new Error('Delete file failed');
        }

        // 删除回收站记录（trash_ 键）
        await db.delete(trashKey);

        // 更新索引：确保从索引中移除
        waitUntil(removeFileFromIndex(context, fileId));

        return new Response(JSON.stringify({
            success: true,
            fileId,
        }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    } catch (error) {
        console.error('Permanently delete from trash failed:', error);
        return new Response(JSON.stringify({
            success: false,
            error: error.message,
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
}
