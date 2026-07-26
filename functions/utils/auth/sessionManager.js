/**
 * 会话管理工具
 * 使用数据库存储会话，通过 HttpOnly Cookie 传递会话 Token
 * 管理端和用户端使用独立的 Cookie（admin_session / user_session）
 */

import { generateSessionToken } from './passwordHash.js';
import { getDatabase } from '../databaseAdapter.js';
import { fetchSecurityConfig } from '../sysConfig.js';
import { normalizeSessionMaxAgeDays, sessionMaxAgeDaysToTtl } from './sessionConfig.js';

const SESSION_PREFIX = 'manage@session@';

// Cookie 名称映射
export const COOKIE_NAMES = {
    admin: 'admin_session',
    user: 'user_session',
};

/**
 * 创建新会话
 * @param {Object} env - 环境变量
 * @param {string} authType - 认证类型 ('admin' | 'user')
 * @param {string} [username] - 用户名（管理员登录时使用）
 * @param {Object} [options] - 额外选项 { ip, userAgent, isRemote }
 * @param {string} [options.ip] - 登录 IP 地址
 * @param {string} [options.userAgent] - User-Agent 字符串
 * @param {boolean} [options.isRemote] - 是否异地登录
 * @returns {Promise<{token: string, cookie: string}>}
 */
export async function createSession(env, authType, username = '', options = {}) {
    // 读取安全策略配置
    const securityConfig = await fetchSecurityConfig(env);
    const accessConfig = securityConfig.access || {};
    const secure = accessConfig.sessionSecure ?? false;
    const rawMaxAgeDays = authType === 'admin'
        ? (accessConfig.adminSessionMaxAge ?? 14)
        : (accessConfig.userSessionMaxAge ?? 14);
    const maxAgeDays = normalizeSessionMaxAgeDays(rawMaxAgeDays);
    const maxAge = sessionMaxAgeDaysToTtl(maxAgeDays);

    const db = getDatabase(env);
    const token = generateSessionToken();
    const now = Date.now();
    const { ip = '', userAgent = '', isRemote = false } = options;
    const deviceInfo = parseUserAgent(userAgent);
    const sessionData = {
        authType,
        username,
        createdAt: now,
        expiresAt: now + maxAge * 1000,
        ip,
        userAgent,
        deviceInfo,
        lastAccessedAt: now,
        isRemote,
    };

    await db.put(`${SESSION_PREFIX}${token}`, JSON.stringify(sessionData), {
        expirationTtl: maxAge,
    });

    const cookieName = COOKIE_NAMES[authType] || 'session';
    const cookie = buildSessionCookie(cookieName, token, maxAge, secure);
    return { token, cookie };
}

/**
 * 验证会话（按 authType 读取对应的 Cookie）
 * @param {Object} env - 环境变量
 * @param {Request} request - 请求对象
 * @param {string} authType - 要验证的认证类型 ('admin' | 'user')
 * @returns {Promise<{valid: boolean, session?: Object}>}
 */
export async function validateSession(env, request, authType) {
    const cookieName = COOKIE_NAMES[authType] || 'session';
    const token = getCookieValue(request, cookieName);
    if (!token) {
        return { valid: false };
    }

    const db = getDatabase(env);
    const sessionStr = await db.get(`${SESSION_PREFIX}${token}`);
    if (!sessionStr) {
        return { valid: false };
    }

    try {
        const session = JSON.parse(sessionStr);
        // 验证 authType 匹配
        if (session.authType !== authType) {
            return { valid: false };
        }
        if (Date.now() > session.expiresAt) {
            await db.delete(`${SESSION_PREFIX}${token}`);
            return { valid: false };
        }
        // 异步更新最后访问时间，不阻塞响应
        session.lastAccessedAt = Date.now();
        const remainingTtl = Math.max(1, Math.floor((session.expiresAt - Date.now()) / 1000));
        db.put(`${SESSION_PREFIX}${token}`, JSON.stringify(session), {
            expirationTtl: remainingTtl,
        }).catch(e => console.error('Failed to update session lastAccessedAt:', e));

        return { valid: true, session };
    } catch {
        return { valid: false };
    }
}

/**
 * 验证任意有效会话（不限 authType，用于 sessionCheck 接口）
 * @param {Object} env - 环境变量
 * @param {Request} request - 请求对象
 * @returns {Promise<{valid: boolean, session?: Object}>}
 */
export async function validateAnySession(env, request) {
    // 优先检查 admin，再检查 user
    const adminResult = await validateSession(env, request, 'admin');
    if (adminResult.valid) return adminResult;

    const userResult = await validateSession(env, request, 'user');
    if (userResult.valid) return userResult;

    return { valid: false };
}

/**
 * 销毁会话
 * @param {Object} env - 环境变量
 * @param {Request} request - 请求对象
 * @param {string} [authType] - 要销毁的认证类型，不传则销毁所有
 * @returns {Promise<string|string[]>} 清除 Cookie 的 Set-Cookie 头
 */
export async function destroySession(env, request, authType) {
    // 读取安全策略配置
    const securityConfig = await fetchSecurityConfig(env);
    const secure = securityConfig.access?.sessionSecure ?? false;

    const db = getDatabase(env);

    if (authType) {
        // 销毁指定类型的会话
        const cookieName = COOKIE_NAMES[authType] || 'session';
        const token = getCookieValue(request, cookieName);
        if (token) {
            await db.delete(`${SESSION_PREFIX}${token}`);
        }
        return buildSessionCookie(cookieName, '', 0, secure);
    } else {
        // 销毁所有类型的会话
        const cookies = [];
        for (const [type, cookieName] of Object.entries(COOKIE_NAMES)) {
            const token = getCookieValue(request, cookieName);
            if (token) {
                await db.delete(`${SESSION_PREFIX}${token}`);
            }
            cookies.push(buildSessionCookie(cookieName, '', 0, secure));
        }
        return cookies;
    }
}

/**
 * 按认证类型批量清除会话
 * @param {Object} env - 环境变量
 * @param {string} authType - 要清除的认证类型 ('admin' | 'user')
 * @returns {Promise<number>} 清除的会话数量
 */
export async function destroySessionsByAuthType(env, authType) {
    const db = getDatabase(env);
    let destroyed = 0;

    let cursor = undefined;
    let hasMore = true;

    while (hasMore) {
        const listOptions = { prefix: SESSION_PREFIX };
        if (cursor) {
            listOptions.cursor = cursor;
        }

        const result = await db.list(listOptions);
        const keys = result.keys || [];

        for (const key of keys) {
            try {
                const sessionStr = await db.get(key.name);
                if (sessionStr) {
                    const session = JSON.parse(sessionStr);
                    if (session.authType === authType) {
                        await db.delete(key.name);
                        destroyed++;
                    }
                }
            } catch {
                await db.delete(key.name);
                destroyed++;
            }
        }

        cursor = result.cursor;
        hasMore = !result.list_complete && cursor;
    }

    return destroyed;
}

/**
 * 列出指定用户的所有在线会话
 * 遍历 manage@session@ 前缀的键，过滤出匹配 authType 和 username 的会话
 * @param {Object} env - 环境变量
 * @param {string} authType - 认证类型 ('admin' | 'user')
 * @param {string} [username] - 用户名
 * @returns {Promise<Array>} 会话列表（不含 token 完整值，只返回前 8 位作为标识）
 */
export async function listSessions(env, authType, username = '') {
    const db = getDatabase(env);
    const sessions = [];

    let cursor = undefined;
    let hasMore = true;

    while (hasMore) {
        const listOptions = { prefix: SESSION_PREFIX };
        if (cursor) {
            listOptions.cursor = cursor;
        }

        const result = await db.list(listOptions);
        const keys = result.keys || [];

        for (const key of keys) {
            try {
                // D1 的 list 可能直接返回 value，KV 则需要单独 get
                let sessionStr = key.value;
                if (sessionStr === undefined || sessionStr === null) {
                    sessionStr = await db.get(key.name);
                }
                if (!sessionStr) continue;

                const session = JSON.parse(sessionStr);
                // 过滤 authType 和 username
                if (session.authType !== authType) continue;
                if ((session.username || '') !== username) continue;
                // 跳过已过期的会话
                if (Date.now() > session.expiresAt) continue;

                const fullToken = key.name.replace(SESSION_PREFIX, '');
                sessions.push({
                    tokenPrefix: fullToken.substring(0, 8),
                    authType: session.authType,
                    username: session.username || '',
                    createdAt: session.createdAt,
                    expiresAt: session.expiresAt,
                    lastAccessedAt: session.lastAccessedAt || session.createdAt,
                    ip: session.ip || '',
                    userAgent: session.userAgent || '',
                    deviceInfo: session.deviceInfo || {},
                    isRemote: session.isRemote || false,
                });
            } catch (e) {
                console.error('Failed to parse session:', e);
            }
        }

        cursor = result.cursor;
        hasMore = !result.list_complete && cursor;
    }

    return sessions;
}

/**
 * 通过 token 销毁指定会话
 * 支持完整 token 或 token 前缀（8 位标识）匹配
 * @param {Object} env - 环境变量
 * @param {string} token - 会话 token（完整或前缀）
 * @returns {Promise<boolean>} 是否成功销毁
 */
export async function destroySessionByToken(env, token) {
    if (!token) return false;

    const db = getDatabase(env);
    const key = `${SESSION_PREFIX}${token}`;

    // 优先尝试完整 token 直接删除
    const sessionStr = await db.get(key);
    if (sessionStr) {
        await db.delete(key);
        return true;
    }

    // 未找到则尝试前缀匹配（token 为前 8 位标识）
    let cursor = undefined;
    let hasMore = true;

    while (hasMore) {
        const listOptions = { prefix: SESSION_PREFIX };
        if (cursor) {
            listOptions.cursor = cursor;
        }

        const result = await db.list(listOptions);
        const keys = result.keys || [];

        for (const k of keys) {
            const fullToken = k.name.replace(SESSION_PREFIX, '');
            if (fullToken.startsWith(token)) {
                await db.delete(k.name);
                return true;
            }
        }

        cursor = result.cursor;
        hasMore = !result.list_complete && cursor;
    }

    return false;
}

/**
 * 销毁指定用户的所有其他会话（保留当前会话）
 * @param {Object} env - 环境变量
 * @param {string} authType - 认证类型 ('admin' | 'user')
 * @param {string} username - 用户名
 * @param {string} currentToken - 当前会话的 token（保留此会话）
 * @returns {Promise<number>} 销毁的会话数量
 */
export async function destroyOtherSessions(env, authType, username, currentToken) {
    const db = getDatabase(env);
    let destroyed = 0;

    let cursor = undefined;
    let hasMore = true;

    while (hasMore) {
        const listOptions = { prefix: SESSION_PREFIX };
        if (cursor) {
            listOptions.cursor = cursor;
        }

        const result = await db.list(listOptions);
        const keys = result.keys || [];

        for (const key of keys) {
            const fullToken = key.name.replace(SESSION_PREFIX, '');
            // 跳过当前会话
            if (currentToken && fullToken === currentToken) continue;

            try {
                let sessionStr = key.value;
                if (sessionStr === undefined || sessionStr === null) {
                    sessionStr = await db.get(key.name);
                }
                if (!sessionStr) continue;

                const session = JSON.parse(sessionStr);
                // 只销毁匹配 authType 和 username 的会话
                if (session.authType !== authType) continue;
                if ((session.username || '') !== (username || '')) continue;

                await db.delete(key.name);
                destroyed++;
            } catch (e) {
                console.error('Failed to destroy session:', e);
            }
        }

        cursor = result.cursor;
        hasMore = !result.list_complete && cursor;
    }

    return destroyed;
}

/**
 * 从 User-Agent 字符串解析设备信息
 * @param {string} userAgent - User-Agent 字符串
 * @returns {{ type: string, browser: string, os: string }} 设备信息
 */
export function parseUserAgent(userAgent) {
    const result = { type: 'desktop', browser: 'Unknown', os: 'Unknown' };

    if (!userAgent || typeof userAgent !== 'string') {
        return result;
    }

    const ua = userAgent.toLowerCase();

    // 设备类型判断
    if (/ipad|tablet|playbook|silk/.test(ua)) {
        result.type = 'tablet';
    } else if (/mobile|iphone|ipod|android.*mobile|windows phone|blackberry|opera mini/.test(ua)) {
        result.type = 'mobile';
    } else {
        result.type = 'desktop';
    }

    // 操作系统判断
    if (/windows nt/.test(ua)) {
        result.os = 'Windows';
    } else if (/iphone|ipad|ipod/.test(ua)) {
        result.os = 'iOS';
    } else if (/mac os x|macintosh/.test(ua)) {
        result.os = 'macOS';
    } else if (/android/.test(ua)) {
        result.os = 'Android';
    } else if (/linux/.test(ua)) {
        result.os = 'Linux';
    } else if (/cros/.test(ua)) {
        result.os = 'Chrome OS';
    }

    // 浏览器判断（注意顺序，避免误匹配）
    if (/edg\//.test(ua)) {
        result.browser = 'Edge';
    } else if (/opr\/|opera/.test(ua)) {
        result.browser = 'Opera';
    } else if (/chrome|crios/.test(ua) && !/chromium/.test(ua)) {
        result.browser = 'Chrome';
    } else if (/firefox|fxios/.test(ua)) {
        result.browser = 'Firefox';
    } else if (/safari/.test(ua) && !/chrome/.test(ua)) {
        result.browser = 'Safari';
    } else if (/msie|trident/.test(ua)) {
        result.browser = 'IE';
    }

    return result;
}

/**
 * 从请求中提取指定 Cookie 的值
 * @param {Request} request - 请求对象
 * @param {string} name - Cookie 名称
 * @returns {string|null}
 */
export function getCookieValue(request, name) {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return null;

    const regex = new RegExp('(^|;\\s*)' + name + '=([^;]+)');
    const match = cookieHeader.match(regex);
    return match ? match[2] : null;
}

/**
 * 构建 Set-Cookie 头的值
 * @param {string} name - Cookie 名称
 * @param {string} token - 会话 Token
 * @param {number} maxAge - 最大存活时间（秒）
 * @param {boolean} secure - 是否添加 Secure 属性
 * @returns {string}
 */
function buildSessionCookie(name, token, maxAge, secure = false) {
    const parts = [
        `${name}=${token}`,
        `Path=/`,
        `HttpOnly`,
        `SameSite=Strict`,
        `Max-Age=${maxAge}`,
    ];
    if (secure) {
        parts.push('Secure');
    }
    return parts.join('; ');
}
