// 查询分片上传进度（断点续传）
import { userAuthCheck, UnauthorizedResponse } from "../utils/auth/userAuth";
import { getDatabase } from '../utils/databaseAdapter.js';

export async function onRequestGet(context) {
    const { request, env, url } = context;

    // 鉴权
    if (!await userAuthCheck(env, url, request, 'upload')) {
        return UnauthorizedResponse('Unauthorized');
    }

    const uploadId = url.searchParams.get('uploadId');
    const totalChunks = parseInt(url.searchParams.get('totalChunks'));

    if (!uploadId || !totalChunks) {
        return new Response(JSON.stringify({ error: 'Missing uploadId or totalChunks' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const db = getDatabase(env);

    // 检查上传会话是否还存在
    const sessionKey = `upload_session_${uploadId}`;
    const sessionData = await db.get(sessionKey);
    if (!sessionData) {
        return new Response(JSON.stringify({
            valid: false,
            error: 'Upload session expired or not found'
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // 查询已完成的分片
    const completedChunks = [];
    for (let i = 0; i < totalChunks; i++) {
        const chunkKey = `chunk_${uploadId}_${i.toString().padStart(3, '0')}`;
        try {
            const chunkRecord = await db.getWithMetadata(chunkKey);
            if (chunkRecord && chunkRecord.metadata && chunkRecord.metadata.status === 'completed') {
                completedChunks.push(i);
            }
        } catch (e) {
            // 分片不存在或读取失败,跳过
        }
    }

    return new Response(JSON.stringify({
        valid: true,
        uploadId,
        totalChunks,
        completedChunks,
        completedCount: completedChunks.length,
        progress: (completedChunks.length / totalChunks * 100).toFixed(1)
    }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
    });
}
