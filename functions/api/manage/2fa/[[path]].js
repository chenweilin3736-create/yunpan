// 双因素认证(2FA)管理 API
// GET/POST /api/manage/2fa?action=status   - 获取 2FA 启用状态
// POST /api/manage/2fa?action=setup        - 生成新的 TOTP 密钥和 otpauth URI
// POST /api/manage/2fa?action=enable       - 验证 TOTP 码并启用 2FA
// POST /api/manage/2fa?action=disable      - 验证 TOTP/密码并禁用 2FA
// POST /api/manage/2fa?action=verify       - 登录时验证 TOTP 码（使用 challenge token，不需要 session）

import { getDatabase } from '../../../utils/databaseAdapter.js';
import { createSession, validateSession } from '../../../utils/auth/sessionManager.js';
import {
    generateSecret,
    verifyTOTP,
    generateOTPAuthURI,
    generateBackupCodes,
} from '../../../utils/auth/totp.js';
import { verifyPassword } from '../../../utils/auth/passwordHash.js';
import { fetchSecurityConfig } from '../../../utils/sysConfig.js';
import { getUser } from '../../../utils/auth/userManager.js';

// ==================== 常量 ====================

const ADMIN_2FA_KEY = 'manage@sysConfig@2fa';
const USER_2FA_PREFIX = 'manage@user@2fa@';
const CHALLENGE_PREFIX = 'manage@2fa_challenge@';
const CHALLENGE_TTL = 300; // 5 分钟（秒）

// ==================== 主路由 ====================

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);

    // 从查询参数或请求体获取 action
    let action = url.searchParams.get('action');
    let body = {};

    if (request.method === 'POST') {
        try {
            body = await request.json();
        } catch {
            // 请求体可能为空或非 JSON
            body = {};
        }
        if (!action) {
            action = body.action;
        }
    }

    try {
        switch (action) {
            case 'status':
                return await handleStatus(context, body);
            case 'setup':
                return await handleSetup(context, body);
            case 'enable':
                return await handleEnable(context, body);
            case 'disable':
                return await handleDisable(context, body);
            case 'verify':
                return await handleVerify(context, body);
            default:
                return jsonRes({ error: '未知操作，请使用 action=status|setup|enable|disable|verify' }, 400);
        }
    } catch (error) {
        console.error('2FA API error:', error);
        return jsonRes({ error: error.message || 'Internal server error' }, 500);
    }
}

// ==================== action=status ====================

/**
 * 获取当前用户的 2FA 启用状态
 */
async function handleStatus(context, body) {
    const { env } = context;
    const { authType, username } = await getAuthContext(context);

    if (!authType) {
        return jsonRes({ error: '未认证' }, 401);
    }

    const db = getDatabase(env);
    const config = await get2FAConfig(db, authType, username);

    return jsonRes({
        enabled: config ? config.enabled === true : false,
        enabledAt: config?.enabledAt || null,
    });
}

// ==================== action=setup ====================

/**
 * 生成新的 TOTP 密钥和 otpauth URI（不自动启用）
 */
async function handleSetup(context, body) {
    const { env } = context;
    const { authType, username } = await getAuthContext(context);

    if (!authType) {
        return jsonRes({ error: '未认证' }, 401);
    }

    // 生成新的密钥
    const secret = generateSecret();

    // 确定账号名称（用于 otpauth URI）
    const accountName = authType === 'admin' ? 'admin' : (username || 'user');
    const otpauthURI = generateOTPAuthURI(secret, accountName);

    return jsonRes({
        secret,
        otpauthURI,
    });
}

// ==================== action=enable ====================

/**
 * 验证 TOTP 码并启用 2FA
 * 请求体: { secret, token }
 */
async function handleEnable(context, body) {
    const { env } = context;
    const { authType, username } = await getAuthContext(context);

    if (!authType) {
        return jsonRes({ error: '未认证' }, 401);
    }

    const { secret, token } = body;

    if (!secret || !token) {
        return jsonRes({ error: '缺少密钥或验证码' }, 400);
    }

    const db = getDatabase(env);

    // 检查是否已启用 2FA
    const existingConfig = await get2FAConfig(db, authType, username);
    if (existingConfig && existingConfig.enabled === true) {
        return jsonRes({ error: '2FA 已启用，请先禁用后再重新设置' }, 400);
    }

    // 验证 TOTP 码
    const isValid = await verifyTOTP(secret, token, 1);
    if (!isValid) {
        return jsonRes({ error: '验证码不正确' }, 401);
    }

    // 生成备用码
    const backupCodes = generateBackupCodes();

    // 保存 2FA 配置
    const config = {
        enabled: true,
        secret,
        backupCodes,
        enabledAt: Date.now(),
    };
    await save2FAConfig(db, authType, username, config);

    return jsonRes({
        success: true,
        backupCodes,
        message: '2FA 已成功启用，请妥善保存备用码',
    });
}

// ==================== action=disable ====================

/**
 * 验证 TOTP/密码并禁用 2FA
 * 请求体: { token } 或 { password } 或 { backupCode }
 */
async function handleDisable(context, body) {
    const { env } = context;
    const { authType, username } = await getAuthContext(context);

    if (!authType) {
        return jsonRes({ error: '未认证' }, 401);
    }

    const db = getDatabase(env);
    const config = await get2FAConfig(db, authType, username);

    if (!config || config.enabled !== true) {
        return jsonRes({ error: '2FA 未启用' }, 400);
    }

    // 验证方式：TOTP 码、密码、或备用码
    const { token, password, backupCode } = body;

    if (token) {
        // 验证 TOTP 码
        const isValid = await verifyTOTP(config.secret, token, 1);
        if (!isValid) {
            return jsonRes({ error: '验证码不正确' }, 401);
        }
    } else if (password) {
        // 验证密码
        const passwordValid = await verifyPasswordForUser(env, authType, username, password);
        if (!passwordValid) {
            return jsonRes({ error: '密码不正确' }, 401);
        }
    } else if (backupCode) {
        // 验证备用码
        const index = config.backupCodes.indexOf(backupCode);
        if (index === -1) {
            return jsonRes({ error: '备用码不正确' }, 401);
        }
    } else {
        return jsonRes({ error: '请提供验证码、密码或备用码' }, 400);
    }

    // 删除 2FA 配置
    await delete2FAConfig(db, authType, username);

    return jsonRes({
        success: true,
        message: '2FA 已禁用',
    });
}

// ==================== action=verify ====================

/**
 * 登录时验证 TOTP 码（使用 challenge token，不需要 session）
 * 请求体: { challenge, token } 或 { challenge, backupCode }
 */
async function handleVerify(context, body) {
    const { env, request } = context;
    const { challenge, token, backupCode } = body;

    if (!challenge) {
        return jsonRes({ error: '缺少 challenge token' }, 400);
    }
    if (!token && !backupCode) {
        return jsonRes({ error: '请提供验证码或备用码' }, 400);
    }

    const db = getDatabase(env);

    // 查找 challenge token
    const challengeStr = await db.get(`${CHALLENGE_PREFIX}${challenge}`);
    if (!challengeStr) {
        return jsonRes({ error: '无效或过期的 challenge token' }, 401);
    }

    let challengeData;
    try {
        challengeData = JSON.parse(challengeStr);
    } catch {
        return jsonRes({ error: 'challenge token 格式错误' }, 401);
    }

    // 检查是否过期
    if (challengeData.expiresAt && Date.now() > challengeData.expiresAt) {
        await db.delete(`${CHALLENGE_PREFIX}${challenge}`);
        return jsonRes({ error: 'challenge token 已过期，请重新登录' }, 401);
    }

    const { authType, username } = challengeData;

    // 获取 2FA 配置
    const config = await get2FAConfig(db, authType, username);
    if (!config || config.enabled !== true) {
        return jsonRes({ error: '2FA 未启用' }, 400);
    }

    // 验证 TOTP 码或备用码
    if (token) {
        const isValid = await verifyTOTP(config.secret, token, 1);
        if (!isValid) {
            return jsonRes({ error: '验证码不正确' }, 401);
        }
    } else if (backupCode) {
        const index = config.backupCodes.indexOf(backupCode);
        if (index === -1) {
            return jsonRes({ error: '备用码不正确' }, 401);
        }
        // 移除已使用的备用码
        config.backupCodes.splice(index, 1);
        await save2FAConfig(db, authType, username, config);
    }

    // 删除已使用的 challenge token（防止重放攻击）
    await db.delete(`${CHALLENGE_PREFIX}${challenge}`);

    // 创建会话（传入 IP 和 UA 信息）
    const sessionUsername = authType === 'admin' ? '' : username;
    const ip = request.headers.get('CF-Connecting-IP')
        || request.headers.get('X-Real-IP')
        || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
        || '';
    const userAgent = request.headers.get('User-Agent') || '';
    const { cookie } = await createSession(env, authType, sessionUsername, { ip, userAgent });

    // 构建响应
    const responseData = { success: true };
    if (authType === 'user') {
        const user = await getUser(db, username);
        responseData.username = username;
        responseData.displayName = user?.displayName || username;
    }

    return new Response(JSON.stringify(responseData), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Set-Cookie': cookie,
        },
    });
}

// ==================== 辅助函数 ====================

/**
 * 从 context 获取认证类型和用户名
 * 优先使用中间件注入的信息，否则独立验证 session（fallback）
 */
async function getAuthContext(context) {
    // 优先使用中间件注入的认证信息
    if (context.authType) {
        return {
            authType: context.authType,
            username: context.authSession?.username || '',
        };
    }

    // fallback：独立验证 session
    const { env, request } = context;

    // 检查 admin session
    const adminResult = await validateSession(env, request, 'admin');
    if (adminResult.valid) {
        return { authType: 'admin', username: '' };
    }

    // 检查 user session（子账号）
    const userResult = await validateSession(env, request, 'user');
    if (userResult.valid && userResult.session?.username) {
        return {
            authType: 'user',
            username: userResult.session.username,
        };
    }

    return { authType: null, username: '' };
}

/**
 * 获取 2FA 配置
 * @param {Object} db - 数据库实例
 * @param {string} authType - 'admin' | 'user'
 * @param {string} username - 用户名（admin 时可为空）
 * @returns {Promise<Object|null>}
 */
async function get2FAConfig(db, authType, username) {
    const key = authType === 'admin'
        ? ADMIN_2FA_KEY
        : `${USER_2FA_PREFIX}${username}`;
    const str = await db.get(key);
    if (!str) return null;
    try {
        return JSON.parse(str);
    } catch {
        return null;
    }
}

/**
 * 保存 2FA 配置
 */
async function save2FAConfig(db, authType, username, config) {
    const key = authType === 'admin'
        ? ADMIN_2FA_KEY
        : `${USER_2FA_PREFIX}${username}`;
    await db.put(key, JSON.stringify(config));
}

/**
 * 删除 2FA 配置
 */
async function delete2FAConfig(db, authType, username) {
    const key = authType === 'admin'
        ? ADMIN_2FA_KEY
        : `${USER_2FA_PREFIX}${username}`;
    await db.delete(key);
}

/**
 * 验证用户密码（用于 disable 操作）
 * @param {Object} env - 环境变量
 * @param {string} authType - 'admin' | 'user'
 * @param {string} username - 用户名
 * @param {string} password - 明文密码
 * @returns {Promise<boolean>}
 */
async function verifyPasswordForUser(env, authType, username, password) {
    if (authType === 'admin') {
        const securityConfig = await fetchSecurityConfig(env);
        const adminPassword = securityConfig.auth.admin.adminPassword;
        if (!adminPassword) {
            // 管理员未配置密码，不允许通过密码禁用
            return false;
        }
        return await verifyPassword(password, adminPassword);
    } else {
        const db = getDatabase(env);
        const user = await getUser(db, username, true);
        if (!user || !user.passwordHash) {
            return false;
        }
        return await verifyPassword(password, user.passwordHash);
    }
}

/**
 * 构建标准 JSON 响应（含 CORS 头）
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
