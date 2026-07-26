// 子账号登录
// POST /api/auth/subLogin
// body: { username, password }

import { getDatabase } from '../../utils/databaseAdapter.js';
import { getUser, verifyUserCredentials } from '../../utils/auth/userManager.js';
import { createSession } from '../../utils/auth/sessionManager.js';

export async function onRequestPost(context) {
    const { request, env } = context;

    try {
        const body = await request.json();
        const { username, password } = body;

        if (!username || !password) {
            return new Response(JSON.stringify({ error: '用户名和密码不能为空' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
            });
        }

        const db = getDatabase(env);

        // 验证用户凭据
        const result = await verifyUserCredentials(db, username, password);
        if (!result.valid) {
            return new Response(JSON.stringify({ error: result.reason || '用户名或密码错误' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
            });
        }

        // 创建 session，authType 传入 username
        const { cookie } = await createSession(env, 'user', username);

        return new Response(JSON.stringify({
            success: true,
            username: result.user.username,
            displayName: result.user.displayName,
        }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Set-Cookie': cookie,
            },
        });
    } catch (error) {
        console.error('Sub login failed:', error);
        return new Response(JSON.stringify({ error: error.message || 'Internal server error' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        });
    }
}
