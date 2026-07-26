import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { verifyPassword, rehashIfNeeded } from "../../utils/auth/passwordHash.js";
import { createSession } from "../../utils/auth/sessionManager.js";
import { getDatabase } from "../../utils/databaseAdapter.js";
import { checkAndRecordLogin } from "../../utils/auth/loginAlert.js";
import { generateChallengeToken } from "../../utils/auth/totp.js";

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

    const { username, password } = await request.json();

    // 获取客户端 IP 和 User-Agent
    const ip = getClientIP(request);
    const userAgent = request.headers.get('User-Agent') || '';

    // 读取安全设置
    let securityConfig;
    try {
        securityConfig = await fetchSecurityConfig(env, { throwOnError: true });
    } catch (error) {
        console.error('Admin login blocked because security config could not be loaded:', error);
        return new Response(JSON.stringify({ error: 'Security config unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
    const adminUsername = securityConfig.auth.admin.adminUsername;
    const adminPassword = securityConfig.auth.admin.adminPassword;

    const usernameConfigured = !!(adminUsername && adminUsername.trim());
    const passwordConfigured = !!(adminPassword && adminPassword.trim());
    const adminConfigured = usernameConfigured || passwordConfigured;

    // 管理员未配置，无需认证，直接创建会话
    if (!adminConfigured) {
        // 检测异地登录
        const loginResult = await checkAndRecordLogin(env, ip, '', 'admin');
        const { cookie } = await createSession(env, 'admin', '', {
            ip,
            userAgent,
            isRemote: loginResult.isRemote,
        });
        return new Response(JSON.stringify({
            success: true,
            ...(loginResult.isRemote ? { loginAlert: true } : {}),
        }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie,
                ...corsHeaders,
            },
        });
    }

    // 如果设置了用户名，则验证用户名
    if (usernameConfigured && username !== adminUsername) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }

    // 如果设置了密码，则验证密码
    if (passwordConfigured) {
        const passwordMatch = await verifyPassword(password, adminPassword);
        if (!passwordMatch) {
            return new Response(JSON.stringify({ error: 'Unauthorized' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 登录成功后，自动升级旧版哈希为 PBKDF2
        await rehashIfNeeded(getDatabase(env), password, adminPassword, 'auth.admin.adminPassword');
    }

    // 检查管理员是否启用了 2FA
    const db = getDatabase(env);
    const twoFAStr = await db.get('manage@sysConfig@2fa');
    if (twoFAStr) {
        try {
            const twoFAConfig = JSON.parse(twoFAStr);
            if (twoFAConfig.enabled === true) {
                // 2FA 已启用，生成 challenge token，不创建会话
                const challengeToken = generateChallengeToken();
                const challengeData = {
                    authType: 'admin',
                    username: 'admin',
                    createdAt: Date.now(),
                    expiresAt: Date.now() + 300 * 1000, // 5 分钟过期
                };
                await db.put(`manage@2fa_challenge@${challengeToken}`, JSON.stringify(challengeData), {
                    expirationTtl: 300,
                });
                return new Response(JSON.stringify({
                    requires2FA: true,
                    challenge: challengeToken,
                    username: 'admin',
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

    // 检测异地登录
    const loginResult = await checkAndRecordLogin(env, ip, '', 'admin');

    // 创建会话并通过 HttpOnly Cookie 返回
    const { cookie } = await createSession(env, 'admin', '', {
        ip,
        userAgent,
        isRemote: loginResult.isRemote,
    });

    return new Response(JSON.stringify({
        success: true,
        ...(loginResult.isRemote ? { loginAlert: true } : {}),
    }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': cookie,
            ...corsHeaders,
        },
    });
}
