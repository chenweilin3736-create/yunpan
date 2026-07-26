// 子账号登录
// POST /api/auth/subLogin
// body: { username, password }

import { getDatabase } from '../../utils/databaseAdapter.js';
import { getUser, verifyUserCredentials } from '../../utils/auth/userManager.js';
import { createSession } from '../../utils/auth/sessionManager.js';
import { checkAndRecordLogin } from '../../utils/auth/loginAlert.js';
import { generateChallengeToken } from '../../utils/auth/totp.js';

/**
 * 从请求头获取客户端 IP 地址
 */
function getClientIP(request) {
    return request.headers.get('CF-Connecting-IP')
        || request.headers.get('X-Real-IP')
        || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
        || '';
}

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

export async function onRequestPost(context) {
    const { request, env } = context;

    try {
        const body = await request.json();
        const { username, password } = body;

        if (!username || !password) {
            return new Response(JSON.stringify({ error: '用户名和密码不能为空' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        const db = getDatabase(env);

        // 验证用户凭据
        const result = await verifyUserCredentials(db, username, password);
        if (!result.valid) {
            return new Response(JSON.stringify({ error: result.reason || '用户名或密码错误' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 检查子账号是否启用了 2FA
        const twoFAStr = await db.get(`manage@user@2fa@${username}`);
        if (twoFAStr) {
            try {
                const twoFAConfig = JSON.parse(twoFAStr);
                if (twoFAConfig.enabled === true) {
                    // 2FA 已启用，生成 challenge token，不创建会话
                    const challengeToken = generateChallengeToken();
                    const challengeData = {
                        authType: 'user',
                        username,
                        createdAt: Date.now(),
                        expiresAt: Date.now() + 300 * 1000, // 5 分钟过期
                    };
                    await db.put(`manage@2fa_challenge@${challengeToken}`, JSON.stringify(challengeData), {
                        expirationTtl: 300,
                    });
                    return new Response(JSON.stringify({
                        requires2FA: true,
                        challenge: challengeToken,
                        username,
                    }), {
                        status: 200,
                        headers: {
                            'Content-Type': 'application/json',
                            ...corsHeaders,
                        },
                    });
                }
            } catch (e) {
                console.error('Failed to check 2FA config:', e);
                // 解析失败时继续正常登录流程（不阻塞登录）
            }
        }

        // 获取客户端 IP 和 User-Agent
        const ip = getClientIP(request);
        const userAgent = request.headers.get('User-Agent') || '';

        // 检测异地登录
        const loginResult = await checkAndRecordLogin(env, ip, username, 'user');

        // 创建 session，传入 IP、UA 和异地登录标记
        const { cookie } = await createSession(env, 'user', username, {
            ip,
            userAgent,
            isRemote: loginResult.isRemote,
        });

        return new Response(JSON.stringify({
            success: true,
            username: result.user.username,
            displayName: result.user.displayName,
            ...(loginResult.isRemote ? { loginAlert: true } : {}),
        }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Set-Cookie': cookie,
                ...corsHeaders,
            },
        });
    } catch (error) {
        console.error('Sub login failed:', error);
        return new Response(JSON.stringify({ error: error.message || 'Internal server error' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', ...corsHeaders },
        });
    }
}
