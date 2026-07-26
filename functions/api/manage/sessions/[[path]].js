/**
 * 在线设备管理 API
 * GET    /api/manage/sessions        - 列出当前登录用户的所有在线会话（设备列表）
 * DELETE /api/manage/sessions/{token} - 通过 session token 标识销毁指定会话（强制下线）
 * POST   /api/manage/sessions?action=destroyAll - 销毁所有其他会话（一键下线所有其他设备）
 */

import { getDatabase } from '../../../utils/databaseAdapter.js';
import {
    validateSession,
    listSessions,
    destroySessionByToken,
    destroyOtherSessions,
    COOKIE_NAMES,
    getCookieValue,
} from '../../../utils/auth/sessionManager.js';

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

/**
 * 构建 JSON 响应
 */
function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            ...corsHeaders,
        },
    });
}

/**
 * 验证当前会话，返回认证类型、会话对象和当前 token
 * 优先检查 admin，再检查 user
 */
async function authenticateSession(env, request) {
    // 优先检查 admin 会话
    const adminResult = await validateSession(env, request, 'admin');
    if (adminResult.valid) {
        const currentToken = getCookieValue(request, COOKIE_NAMES.admin);
        return {
            authType: 'admin',
            session: adminResult.session,
            currentToken,
        };
    }

    // 再检查 user 会话
    const userResult = await validateSession(env, request, 'user');
    if (userResult.valid) {
        const currentToken = getCookieValue(request, COOKIE_NAMES.user);
        return {
            authType: 'user',
            session: userResult.session,
            currentToken,
        };
    }

    return null;
}

/**
 * 从路径参数或请求体获取 token
 */
async function extractToken(request, params) {
    // 1. 从路径参数获取
    if (params?.path) {
        const pathParts = Array.isArray(params.path) ? params.path : [params.path];
        if (pathParts.length > 0 && pathParts[0]) {
            return decodeURIComponent(pathParts[0]);
        }
    }

    // 2. 从请求体获取
    try {
        const body = await request.json();
        if (body.token) {
            return body.token;
        }
    } catch (e) {
        // 请求体不是 JSON 或为空，忽略
    }

    return null;
}

export async function onRequest(context) {
    const { request, env, params } = context;

    // OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: corsHeaders,
        });
    }

    // 验证当前会话
    const authInfo = await authenticateSession(env, request);
    if (!authInfo) {
        return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const { authType, session, currentToken } = authInfo;
    const username = session.username || '';
    const url = new URL(request.url);

    // GET: 列出当前登录用户的所有在线会话（设备列表）
    if (request.method === 'GET') {
        try {
            const sessions = await listSessions(env, authType, username);
            // 标记当前设备并返回完整设备信息
            const currentTokenPrefix = currentToken ? currentToken.substring(0, 8) : '';
            const deviceList = sessions.map(s => ({
                ...s,
                isCurrent: s.tokenPrefix === currentTokenPrefix,
            }));

            return jsonResponse({
                success: true,
                sessions: deviceList,
            });
        } catch (e) {
            console.error('Failed to list sessions:', e);
            return jsonResponse({ error: 'Failed to list sessions' }, 500);
        }
    }

    // DELETE: 通过 session token 标识销毁指定会话（强制下线）
    if (request.method === 'DELETE') {
        try {
            const token = await extractToken(request, params);

            if (!token) {
                return jsonResponse({ error: 'Token is required' }, 400);
            }

            // 不允许通过此接口销毁当前会话
            if (currentToken && (token === currentToken || currentToken.startsWith(token) || token.startsWith(currentToken.substring(0, 8)))) {
                return jsonResponse({ error: 'Cannot destroy current session via this endpoint, please use logout' }, 400);
            }

            const destroyed = await destroySessionByToken(env, token);
            if (destroyed) {
                return jsonResponse({ success: true });
            } else {
                return jsonResponse({ error: 'Session not found' }, 404);
            }
        } catch (e) {
            console.error('Failed to destroy session:', e);
            return jsonResponse({ error: 'Failed to destroy session' }, 500);
        }
    }

    // POST: 销毁所有其他会话（一键下线所有其他设备）
    if (request.method === 'POST') {
        const action = url.searchParams.get('action');

        if (action === 'destroyAll') {
            try {
                const count = await destroyOtherSessions(env, authType, username, currentToken);
                return jsonResponse({
                    success: true,
                    destroyed: count,
                });
            } catch (e) {
                console.error('Failed to destroy other sessions:', e);
                return jsonResponse({ error: 'Failed to destroy other sessions' }, 500);
            }
        }

        return jsonResponse({ error: 'Unknown action, supported: destroyAll' }, 400);
    }

    return jsonResponse({ error: 'Method not allowed' }, 405);
}
