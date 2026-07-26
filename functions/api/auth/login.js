import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { verifyPassword, rehashIfNeeded } from "../../utils/auth/passwordHash.js";
import { createSession } from "../../utils/auth/sessionManager.js";
import { checkAndRecordLogin } from "../../utils/auth/loginAlert.js";
import { getDatabase } from "../../utils/databaseAdapter.js";

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

    const jsonRequest = await request.json();
    const authCode = jsonRequest.authCode;

    // 获取客户端 IP 和 User-Agent
    const ip = getClientIP(request);
    const userAgent = request.headers.get('User-Agent') || '';

    // 读取安全设置
    let securityConfig;
    try {
        securityConfig = await fetchSecurityConfig(env, { throwOnError: true });
    } catch (error) {
        console.error('User login blocked because security config could not be loaded:', error);
        return new Response(JSON.stringify({ error: 'Security config unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
    const rightAuthCode = securityConfig.auth.user.authCode;

    // 验证 authCode（兼容明文、SHA-256 和 PBKDF2 三种存储格式）
    if (rightAuthCode !== undefined && rightAuthCode !== '') {
        const isValid = await verifyPassword(authCode, rightAuthCode);
        if (!isValid) {
            return new Response(JSON.stringify({ error: 'Unauthorized' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 登录成功后，自动升级旧版哈希为 PBKDF2
        await rehashIfNeeded(getDatabase(env), authCode, rightAuthCode, 'auth.user.authCode');
    }

    // 检测异地登录
    const loginResult = await checkAndRecordLogin(env, ip, '', 'user');

    // 创建会话并通过 HttpOnly Cookie 返回
    const { cookie } = await createSession(env, 'user', '', {
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
