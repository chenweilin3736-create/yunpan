/**
 * 异地登录检测工具
 * 通过记录常用 IP 列表，检测并提醒异地登录行为
 * 使用 Web Crypto API，不引入外部依赖
 */

import { getDatabase } from '../databaseAdapter.js';

const LOGIN_IPS_PREFIX = 'manage@loginIPs@';
const LOGIN_ALERT_PREFIX = 'manage@loginAlert@';
const MAX_KNOWN_IPS = 20;

/**
 * 从 IP 地址提取区域标识（前 3 位用于 IPv4）
 * 用于判断是否为同一地区
 * @param {string} ip - IP 地址
 * @returns {string} 区域标识
 */
function getIpRegion(ip) {
    if (!ip) return '';
    const parts = ip.split('.');
    if (parts.length === 4) {
        // IPv4: 取前 3 段作为区域标识
        return parts.slice(0, 3).join('.');
    }
    // IPv6 或其他格式: 直接使用完整 IP
    return ip;
}

/**
 * 判断两个 IP 是否属于同一区域
 * @param {string} ip1 - IP 地址 1
 * @param {string} ip2 - IP 地址 2
 * @returns {boolean}
 */
function isSameRegion(ip1, ip2) {
    if (!ip1 || !ip2) return false;
    return getIpRegion(ip1) === getIpRegion(ip2);
}

/**
 * 检查并记录登录，判断是否为异地登录
 * 登录时调用，检查 IP 是否为常用 IP：
 * - 从 KV 读取 manage@loginIPs@{authType}@{username} 获取常用 IP 列表
 * - 如果 IP 不在列表中（前3位匹配视为同一地区），标记为异地登录
 * - 将新 IP 加入常用 IP 列表（最多保留 20 个）
 * - 如果是异地登录，创建提醒记录
 * @param {Object} env - 环境变量
 * @param {string} ip - 登录 IP 地址
 * @param {string} username - 用户名
 * @param {string} authType - 认证类型 ('admin' | 'user')
 * @returns {Promise<{isRemote: boolean, alertId?: string}>}
 */
export async function checkAndRecordLogin(env, ip, username, authType) {
    const db = getDatabase(env);
    const ipListKey = `${LOGIN_IPS_PREFIX}${authType}@${username}`;

    // 读取常用 IP 列表
    let knownIPs = [];
    try {
        const data = await db.get(ipListKey);
        if (data) {
            knownIPs = JSON.parse(data);
            if (!Array.isArray(knownIPs)) {
                knownIPs = [];
            }
        }
    } catch (e) {
        console.error('Failed to read known IPs:', e);
    }

    // 检查 IP 是否为常用 IP（前 3 位匹配视为同一地区）
    let isRemote = false;
    if (ip) {
        isRemote = !knownIPs.some(knownIP => isSameRegion(ip, knownIP));

        // 将新 IP 加入常用 IP 列表
        if (!knownIPs.includes(ip)) {
            knownIPs.push(ip);
            // 最多保留 20 个
            if (knownIPs.length > MAX_KNOWN_IPS) {
                knownIPs = knownIPs.slice(-MAX_KNOWN_IPS);
            }
            try {
                await db.put(ipListKey, JSON.stringify(knownIPs));
            } catch (e) {
                console.error('Failed to save known IPs:', e);
            }
        }
    }

    // 如果是异地登录，创建提醒记录
    let alertId;
    if (isRemote && ip) {
        const timestamp = Date.now();
        const random = crypto.randomUUID();
        alertId = `${timestamp}_${random}`;
        const alertKey = `${LOGIN_ALERT_PREFIX}${alertId}`;
        const alertData = {
            username,
            authType,
            ip,
            timestamp,
            read: false,
        };
        try {
            await db.put(alertKey, JSON.stringify(alertData));
        } catch (e) {
            console.error('Failed to create login alert:', e);
        }
    }

    return { isRemote, alertId };
}

/**
 * 获取未读的异地登录提醒列表
 * @param {Object} env - 环境变量
 * @param {string} username - 用户名
 * @param {string} authType - 认证类型 ('admin' | 'user')
 * @returns {Promise<Array>} 提醒列表
 */
export async function getLoginAlerts(env, username, authType) {
    const db = getDatabase(env);
    const alerts = [];

    let cursor = undefined;
    let hasMore = true;

    while (hasMore) {
        const listOptions = { prefix: LOGIN_ALERT_PREFIX };
        if (cursor) {
            listOptions.cursor = cursor;
        }

        const result = await db.list(listOptions);
        const keys = result.keys || [];

        for (const key of keys) {
            try {
                // D1 的 list 可能直接返回 value，KV 则需要单独 get
                let alertStr = key.value;
                if (alertStr === undefined || alertStr === null) {
                    alertStr = await db.get(key.name);
                }
                if (!alertStr) continue;

                const alert = JSON.parse(alertStr);
                // 过滤指定用户和认证类型，且未读
                if (alert.username !== username) continue;
                if (alert.authType !== authType) continue;
                if (alert.read) continue;

                alerts.push({
                    alertId: key.name.replace(LOGIN_ALERT_PREFIX, ''),
                    username: alert.username,
                    authType: alert.authType,
                    ip: alert.ip,
                    timestamp: alert.timestamp,
                    read: alert.read,
                });
            } catch (e) {
                console.error('Failed to parse login alert:', e);
            }
        }

        cursor = result.cursor;
        hasMore = !result.list_complete && cursor;
    }

    // 按时间倒序排列
    alerts.sort((a, b) => b.timestamp - a.timestamp);
    return alerts;
}

/**
 * 标记提醒为已读
 * @param {Object} env - 环境变量
 * @param {string} alertId - 提醒 ID（timestamp_random 格式）
 * @returns {Promise<boolean>} 是否成功
 */
export async function markAlertRead(env, alertId) {
    if (!alertId) return false;

    const db = getDatabase(env);
    const alertKey = `${LOGIN_ALERT_PREFIX}${alertId}`;

    try {
        const data = await db.get(alertKey);
        if (!data) return false;

        const alert = JSON.parse(data);
        alert.read = true;
        await db.put(alertKey, JSON.stringify(alert));
        return true;
    } catch (e) {
        console.error('Failed to mark alert as read:', e);
        return false;
    }
}

/**
 * 获取常用 IP 列表
 * @param {Object} env - 环境变量
 * @param {string} username - 用户名
 * @param {string} authType - 认证类型 ('admin' | 'user')
 * @returns {Promise<Array<string>>} IP 列表
 */
export async function getKnownIPs(env, username, authType) {
    const db = getDatabase(env);
    const ipListKey = `${LOGIN_IPS_PREFIX}${authType}@${username}`;

    try {
        const data = await db.get(ipListKey);
        if (data) {
            const ips = JSON.parse(data);
            if (Array.isArray(ips)) {
                return ips;
            }
        }
    } catch (e) {
        console.error('Failed to read known IPs:', e);
    }

    return [];
}
