// 操作日志 API
// GET /api/manage/logs?limit=50&offset=0&username=&action= - 获取操作日志
// POST /api/manage/logs - 记录操作日志
// DELETE /api/manage/logs?action=clear - 清空日志
// DELETE /api/manage/logs?action=clear&before=timestamp - 清空指定时间之前的日志

import { getDatabase } from '../../utils/databaseAdapter.js';
import { logOperation, getLogs, clearLogs } from '../../utils/auth/userManager.js';

// 合法的操作类型
const VALID_ACTIONS = [
    'upload', 'delete', 'download', 'share', 'login',
    'rename', 'move', 'copy', 'config_change', 'user_create', 'user_delete'
];

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const db = getDatabase(env);
    const ip = request.headers.get('CF-Connecting-IP') || '';

    try {
        // GET: 获取操作日志
        if (request.method === 'GET') {
            const limit = parseInt(url.searchParams.get('limit'), 10) || 50;
            const offset = parseInt(url.searchParams.get('offset'), 10) || 0;
            const username = url.searchParams.get('username') || '';
            const action = url.searchParams.get('action') || '';

            const result = await getLogs(db, { limit, offset, username, action });
            return jsonRes(result);
        }

        // POST: 记录操作日志
        if (request.method === 'POST') {
            const body = await request.json();
            const { action, fileId, fileName, details, username } = body;

            if (!action || !VALID_ACTIONS.includes(action)) {
                return jsonRes({
                    error: `Invalid action. Must be one of: ${VALID_ACTIONS.join(', ')}`
                }, 400);
            }

            const result = await logOperation(db, {
                action,
                fileId: fileId || null,
                fileName: fileName || null,
                details: details || '',
                username: username || 'anonymous',
                ip,
            });

            return jsonRes(result);
        }

        // DELETE: 清空日志
        if (request.method === 'DELETE') {
            const action = url.searchParams.get('action');
            if (action !== 'clear') {
                return jsonRes({ error: 'Only action=clear is supported for DELETE' }, 400);
            }

            const before = url.searchParams.get('before');
            const beforeTimestamp = before ? parseInt(before, 10) : null;

            const result = await clearLogs(db, beforeTimestamp);
            return jsonRes(result);
        }

        return jsonRes({ error: 'Method not allowed' }, 405);
    } catch (error) {
        console.error('Error in logs API:', error);
        return jsonRes({ error: error.message || 'Internal server error' }, 500);
    }
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
