/**
 * 用户管理工具
 * 提供子账号的 CRUD、密码哈希/验证、权限检查和操作日志功能
 */

import { hashPassword, verifyPassword, validatePasswordStrength } from './passwordHash.js';

// ==================== 常量 ====================

const USER_KEY_PREFIX = 'manage@user@';
const LOG_KEY_PREFIX = 'manage@log@';
const VALID_PERMISSIONS = ['read', 'upload', 'delete'];
const VALID_ACTIONS = ['upload', 'delete', 'download', 'share', 'login', 'rename', 'move', 'copy', 'config_change', 'user_create', 'user_delete'];

// ==================== 密码哈希和验证 ====================

/**
 * 对密码进行 PBKDF2-SHA256 哈希
 * 复用项目已有的 passwordHash.js 中的 hashPassword 函数
 * @param {string} password - 明文密码
 * @returns {Promise<{hash: string, salt: string}>} hash 为完整哈希字符串（含前缀），salt 为十六进制盐值
 */
export async function hashUserPassword(password) {
    if (!password || typeof password !== 'string') {
        throw new Error('密码不能为空');
    }
    const hashed = await hashPassword(password);
    // hashed 格式: $pbkdf2$salt$hash
    const parts = hashed.split('$');
    // ['', 'pbkdf2', salt, hash]
    return {
        hash: hashed,
        salt: parts[2] || ''
    };
}

/**
 * 验证密码是否匹配
 * @param {string} password - 用户输入的明文密码
 * @param {string} storedHash - 数据库中存储的哈希字符串
 * @param {string} salt - 盐值（十六进制，当前实现中未单独使用，因 hash 已包含 salt）
 * @returns {Promise<boolean>} 是否匹配
 */
export async function verifyUserPassword(password, storedHash, salt) {
    if (!password || !storedHash) {
        return false;
    }
    return await verifyPassword(password, storedHash);
}

// ==================== 用户 CRUD ====================

/**
 * 创建子账号
 * @param {Object} db - 数据库适配器实例（通过 getDatabase 获取）
 * @param {Object} userData - 用户数据
 * @param {string} userData.username - 用户名
 * @param {string} userData.password - 明文密码
 * @param {string} [userData.displayName] - 显示名称
 * @param {string[]} [userData.allowedDirs] - 允许访问的目录列表
 * @param {number} [userData.quota] - 配额（MB），默认 1024
 * @param {string[]} [userData.permissions] - 权限列表
 * @param {boolean} [userData.enabled] - 是否启用，默认 true
 * @returns {Promise<Object>} 创建结果 { success, user? }
 * @throws {Error} 用户名已存在或参数无效时抛出错误
 */
export async function createUser(db, userData) {
    const { username, password, displayName, allowedDirs, quota, permissions, enabled } = userData;

    if (!username || typeof username !== 'string' || username.trim() === '') {
        throw new Error('用户名不能为空');
    }

    // 检查用户名合法性（只允许字母、数字、下划线、短横线）
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        throw new Error('用户名只能包含字母、数字、下划线和短横线');
    }

    if (username === 'admin') {
        throw new Error('不能使用 admin 作为子账号用户名');
    }

    if (!password || typeof password !== 'string') {
        throw new Error('密码不能为空');
    }

    const strengthCheck = validatePasswordStrength(password);
    if (!strengthCheck.valid) {
        throw new Error(`${strengthCheck.message}：${strengthCheck.suggestions.join('；')}`);
    }

    // 检查用户名是否已存在
    const existing = await db.get(`${USER_KEY_PREFIX}${username}`);
    if (existing) {
        throw new Error('用户名已存在');
    }

    // 哈希密码
    const { hash, salt } = await hashUserPassword(password);

    const now = Date.now();
    const user = {
        username,
        passwordHash: hash,
        salt,
        displayName: displayName || username,
        allowedDirs: (Array.isArray(allowedDirs) && allowedDirs.length > 0) ? allowedDirs : ['/'],
        quota: typeof quota === 'number' && quota > 0 ? quota : 1024,
        quotaUsed: 0,
        permissions: Array.isArray(permissions) ? permissions.filter(p => VALID_PERMISSIONS.includes(p)) : ['read'],
        enabled: enabled !== false,
        createdAt: now,
        updatedAt: now
    };

    await db.put(`${USER_KEY_PREFIX}${username}`, JSON.stringify(user));

    // 返回时移除密码哈希
    const safeUser = { ...user };
    delete safeUser.passwordHash;
    delete safeUser.salt;

    return { success: true, user: safeUser };
}

/**
 * 获取单个用户信息
 * @param {Object} db - 数据库适配器实例
 * @param {string} username - 用户名
 * @param {boolean} [includeSensitive=false] - 是否包含敏感信息（密码哈希、盐值）
 * @returns {Promise<Object|null>} 用户对象，不存在时返回 null
 */
export async function getUser(db, username, includeSensitive = false) {
    if (!username) return null;

    const data = await db.get(`${USER_KEY_PREFIX}${username}`);
    if (!data) return null;

    try {
        const user = JSON.parse(data);
        if (includeSensitive) {
            return user;
        }
        // 移除敏感信息
        const safeUser = { ...user };
        delete safeUser.passwordHash;
        delete safeUser.salt;
        return safeUser;
    } catch (e) {
        console.error(`Failed to parse user data for ${username}:`, e);
        return null;
    }
}

/**
 * 更新用户信息（支持部分更新）
 * @param {Object} db - 数据库适配器实例
 * @param {string} username - 用户名
 * @param {Object} updates - 要更新的字段
 * @param {string} [updates.displayName] - 显示名称
 * @param {string[]} [updates.allowedDirs] - 允许访问的目录列表
 * @param {number} [updates.quota] - 配额（MB）
 * @param {string[]} [updates.permissions] - 权限列表
 * @param {boolean} [updates.enabled] - 是否启用
 * @param {string} [updates.password] - 新密码（明文，传了则更新密码）
 * @returns {Promise<Object>} 更新结果 { success, user? }
 * @throws {Error} 用户不存在时抛出错误
 */
export async function updateUser(db, username, updates) {
    if (!username) {
        throw new Error('用户名不能为空');
    }

    // 获取完整用户数据（含敏感信息）
    const existingData = await db.get(`${USER_KEY_PREFIX}${username}`);
    if (!existingData) {
        throw new Error('用户不存在');
    }

    const user = JSON.parse(existingData);

    // 更新密码
    if (updates.password !== undefined && updates.password !== null && updates.password !== '') {
        if (typeof updates.password !== 'string') {
            throw new Error('密码格式无效');
        }
        const strengthCheck = validatePasswordStrength(updates.password);
        if (!strengthCheck.valid) {
            throw new Error(`${strengthCheck.message}：${strengthCheck.suggestions.join('；')}`);
        }
        const { hash, salt } = await hashUserPassword(updates.password);
        user.passwordHash = hash;
        user.salt = salt;
    }

    // 更新显示名称
    if (updates.displayName !== undefined) {
        user.displayName = updates.displayName;
    }

    // 更新允许目录
    if (Array.isArray(updates.allowedDirs)) {
        user.allowedDirs = updates.allowedDirs;
    }

    // 更新配额
    if (typeof updates.quota === 'number' && updates.quota > 0) {
        user.quota = updates.quota;
    }

    // 更新权限
    if (Array.isArray(updates.permissions)) {
        user.permissions = updates.permissions.filter(p => VALID_PERMISSIONS.includes(p));
    }

    // 更新启用状态
    if (updates.enabled !== undefined) {
        user.enabled = Boolean(updates.enabled);
    }

    user.updatedAt = Date.now();

    await db.put(`${USER_KEY_PREFIX}${username}`, JSON.stringify(user));

    // 返回时移除敏感信息
    const safeUser = { ...user };
    delete safeUser.passwordHash;
    delete safeUser.salt;

    return { success: true, user: safeUser };
}

/**
 * 删除用户
 * @param {Object} db - 数据库适配器实例
 * @param {string} username - 用户名
 * @returns {Promise<Object>} 删除结果 { success }
 * @throws {Error} 用户不存在或为 admin 时抛出错误
 */
export async function deleteUser(db, username) {
    if (!username) {
        throw new Error('用户名不能为空');
    }

    if (username === 'admin') {
        throw new Error('不能删除 admin 账号');
    }

    const existing = await db.get(`${USER_KEY_PREFIX}${username}`);
    if (!existing) {
        throw new Error('用户不存在');
    }

    await db.delete(`${USER_KEY_PREFIX}${username}`);

    return { success: true, message: `用户 ${username} 已删除` };
}

/**
 * 列出所有子账号
 * @param {Object} db - 数据库适配器实例
 * @returns {Promise<Object>} { success, users: Array }
 */
export async function listUsers(db) {
    const result = await db.list({ prefix: USER_KEY_PREFIX });
    const users = [];

    if (result.keys) {
        for (const key of result.keys) {
            try {
                const data = await db.get(key.name);
                if (data) {
                    const user = JSON.parse(data);
                    // 移除敏感信息
                    const safeUser = { ...user };
                    delete safeUser.passwordHash;
                    delete safeUser.salt;
                    users.push(safeUser);
                }
            } catch (e) {
                console.error(`Failed to parse user at ${key.name}:`, e);
            }
        }
    }

    // 按创建时间倒序
    users.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    return { success: true, users };
}

/**
 * 验证用户凭据
 * @param {Object} db - 数据库适配器实例
 * @param {string} username - 用户名
 * @param {string} password - 明文密码
 * @returns {Promise<{valid: boolean, user?: Object, reason?: string}>}
 */
export async function verifyUserCredentials(db, username, password) {
    if (!username || !password) {
        return { valid: false, reason: '用户名和密码不能为空' };
    }

    const user = await getUser(db, username, true);
    if (!user) {
        return { valid: false, reason: '用户不存在' };
    }

    if (!user.enabled) {
        return { valid: false, reason: '用户已被禁用' };
    }

    const passwordMatch = await verifyUserPassword(password, user.passwordHash, user.salt);
    if (!passwordMatch) {
        return { valid: false, reason: '密码错误' };
    }

    // 返回时移除敏感信息
    const safeUser = { ...user };
    delete safeUser.passwordHash;
    delete safeUser.salt;

    return { valid: true, user: safeUser };
}

// ==================== 权限检查 ====================

/**
 * 检查用户是否拥有某权限
 * @param {Object} user - 用户对象
 * @param {string} permission - 要检查的权限 ('read'|'upload'|'delete')
 * @returns {boolean}
 */
export function checkPermission(user, permission) {
    if (!user) return false;
    // admin 拥有所有权限
    if (user.username === 'admin') return true;
    if (!Array.isArray(user.permissions)) return false;
    return user.permissions.includes(permission);
}

/**
 * 检查用户是否可访问某目录
 * 如果用户未配置 allowedDirs 或 allowedDirs 包含 '/'，则允许访问所有目录
 * @param {Object} user - 用户对象
 * @param {string} dirPath - 目录路径（如 '/docs' 或 '/photos/sub'）
 * @returns {boolean}
 */
export function checkDirAccess(user, dirPath) {
    if (!user) return false;
    // admin 可访问所有目录
    if (user.username === 'admin') return true;
    if (!Array.isArray(user.allowedDirs) || user.allowedDirs.length === 0) {
        return true;
    }

    // 标准化目录路径
    const normalizedPath = dirPath.startsWith('/') ? dirPath : '/' + dirPath;

    // 如果 allowedDirs 包含根目录 '/'，允许所有访问
    if (user.allowedDirs.includes('/')) {
        return true;
    }

    // 检查是否匹配任一允许的目录（前缀匹配）
    return user.allowedDirs.some(dir => {
        const normalizedDir = dir.startsWith('/') ? dir : '/' + dir;
        return normalizedPath === normalizedDir || normalizedPath.startsWith(normalizedDir + '/');
    });
}

// ==================== 操作日志 ====================

/**
 * 生成日志键（包含时间戳和随机后缀，确保唯一且按时间排序）
 * @returns {string} 日志存储键
 */
function generateLogKey() {
    const timestamp = Date.now();
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    const random = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${LOG_KEY_PREFIX}${timestamp}_${random}`;
}

/**
 * 记录操作日志
 * @param {Object} db - 数据库适配器实例
 * @param {Object} logData - 日志数据
 * @param {string} logData.action - 操作类型
 * @param {string} [logData.fileId] - 文件 ID
 * @param {string} [logData.fileName] - 文件名
 * @param {string} [logData.details] - 操作详情
 * @param {string} [logData.username] - 操作用户
 * @param {string} [logData.ip] - 客户端 IP
 * @returns {Promise<Object>} { success, logKey }
 */
export async function logOperation(db, logData) {
    const { action, fileId, fileName, details, username, ip } = logData;

    if (!action) {
        throw new Error('action 不能为空');
    }

    const logKey = generateLogKey();
    const logEntry = {
        action,
        fileId: fileId || null,
        fileName: fileName || null,
        details: details || '',
        username: username || 'anonymous',
        ip: ip || '',
        timestamp: Date.now()
    };

    await db.put(logKey, JSON.stringify(logEntry));

    return { success: true, logKey };
}

/**
 * 获取操作日志列表
 * @param {Object} db - 数据库适配器实例
 * @param {Object} [options] - 查询选项
 * @param {number} [options.limit=50] - 返回条数
 * @param {number} [options.offset=0] - 偏移量
 * @param {string} [options.username] - 按用户名筛选
 * @param {string} [options.action] - 按操作类型筛选
 * @returns {Promise<{success: boolean, logs: Array, total: number}>}
 */
export async function getLogs(db, options = {}) {
    const {
        limit = 50,
        offset = 0,
        username = '',
        action = ''
    } = options;

    const allLogs = [];
    let cursor = undefined;
    let hasMore = true;

    // 遍历所有日志键（按键名排序即按时间排序）
    while (hasMore) {
        const listOptions = { prefix: LOG_KEY_PREFIX };
        if (cursor) {
            listOptions.cursor = cursor;
        }

        const result = await db.list(listOptions);
        const keys = result.keys || [];

        for (const key of keys) {
            try {
                const data = await db.get(key.name);
                if (data) {
                    const log = JSON.parse(data);
                    allLogs.push(log);
                }
            } catch (e) {
                console.error(`Failed to parse log at ${key.name}:`, e);
            }
        }

        cursor = result.cursor;
        hasMore = !result.list_complete && cursor;
    }

    // 按时间戳倒序排列
    allLogs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

    // 过滤
    let filtered = allLogs;
    if (username) {
        filtered = filtered.filter(log => log.username === username);
    }
    if (action) {
        filtered = filtered.filter(log => log.action === action);
    }

    const total = filtered.length;
    const logs = filtered.slice(offset, offset + limit);

    return { success: true, logs, total };
}

/**
 * 清空操作日志
 * @param {Object} db - 数据库适配器实例
 * @param {number|null} [beforeTimestamp=null] - 清空该时间戳之前的日志，null 表示清空所有
 * @returns {Promise<{success: boolean, deleted: number}>}
 */
export async function clearLogs(db, beforeTimestamp = null) {
    let deleted = 0;
    let cursor = undefined;
    let hasMore = true;

    while (hasMore) {
        const listOptions = { prefix: LOG_KEY_PREFIX };
        if (cursor) {
            listOptions.cursor = cursor;
        }

        const result = await db.list(listOptions);
        const keys = result.keys || [];

        for (const key of keys) {
            try {
                if (beforeTimestamp !== null) {
                    // 从键名中提取时间戳: manage@log@{timestamp}_{random}
                    const keyParts = key.name.replace(LOG_KEY_PREFIX, '').split('_');
                    const logTimestamp = parseInt(keyParts[0], 10);
                    if (logTimestamp >= beforeTimestamp) {
                        continue; // 保留该时间之后的日志
                    }
                }
                await db.delete(key.name);
                deleted++;
            } catch (e) {
                console.error(`Failed to delete log at ${key.name}:`, e);
            }
        }

        cursor = result.cursor;
        hasMore = !result.list_complete && cursor;
    }

    return { success: true, deleted };
}
