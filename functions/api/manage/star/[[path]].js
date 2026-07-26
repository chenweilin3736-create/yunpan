// 星标收藏 API
// GET /api/manage/star/{fileId} - 获取文件星标状态
// POST /api/manage/star/{fileId} - 切换星标
// GET /api/manage/star?action=list - 获取所有星标文件列表

import { getDatabase } from '../../../utils/databaseAdapter.js';
import { addFileToIndex, readIndex } from '../../../utils/indexManager.js';
import { cleanPersistedMetadata } from '../../../utils/metadata/metadataSecurity.js';

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const db = getDatabase(env);

    try {
        // action=list: 获取所有星标文件
        if (request.method === 'GET') {
            const action = url.searchParams.get('action');
            if (action === 'list') {
                return await handleListStarred(context, db);
            }

            // 获取单个文件的星标状态
            const fileId = decodeURIComponent(params.path || '').split(',').join('/');
            if (!fileId) {
                return jsonRes({ error: 'fileId is required' }, 400);
            }
            return await handleGetStarred(db, fileId);
        }

        if (request.method === 'POST') {
            const fileId = decodeURIComponent(params.path || '').split(',').join('/');
            if (!fileId) {
                return jsonRes({ error: 'fileId is required' }, 400);
            }
            return await handleToggleStar(context, db, fileId);
        }

        return jsonRes({ error: 'Method not allowed' }, 405);
    } catch (error) {
        console.error('Error in star API:', error);
        return jsonRes({ error: error.message || 'Internal server error' }, 500);
    }
}

/**
 * 获取单个文件的星标状态
 */
async function handleGetStarred(db, fileId) {
    const fileData = await db.getWithMetadata(fileId);
    if (!fileData || !fileData.metadata) {
        return jsonRes({ error: 'File not found' }, 404);
    }

    const starred = !!fileData.metadata.Starred;
    return jsonRes({ success: true, fileId, starred });
}

/**
 * 切换文件星标状态
 */
async function handleToggleStar(context, db, fileId) {
    const fileData = await db.getWithMetadata(fileId);
    if (!fileData || !fileData.metadata) {
        return jsonRes({ error: 'File not found' }, 404);
    }

    const body = await context.request.json();
    const { starred } = body;

    if (typeof starred !== 'boolean') {
        return jsonRes({ error: 'starred must be a boolean' }, 400);
    }

    // 更新 metadata 中的 Starred 字段
    const updatedMetadata = { ...fileData.metadata };
    updatedMetadata.Starred = starred;
    const metadataToSave = cleanPersistedMetadata(updatedMetadata);

    // 写回数据库
    await db.put(fileId, fileData.value, { metadata: metadataToSave });

    // 同步更新索引
    context.waitUntil(addFileToIndex(context, fileId, metadataToSave));

    return jsonRes({ success: true, fileId, starred });
}

/**
 * 获取所有星标文件列表
 */
async function handleListStarred(context, db) {
    // 读取全部索引文件，然后过滤 Starred === true
    const result = await readIndex(context, {
        count: 99999, // 读取所有
    });

    if (!result.success) {
        return jsonRes({ success: true, starredFiles: [], total: 0 });
    }

    const starredFiles = result.files
        .filter(file => file.metadata && file.metadata.Starred === true)
        .map(file => ({
            id: file.id,
            metadata: file.metadata,
        }));

    return jsonRes({ success: true, starredFiles, total: starredFiles.length });
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
