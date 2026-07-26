// 子账号管理 API
// GET /api/manage/users - 列出所有子账号
// GET /api/manage/users?action=self - 获取当前用户信息
// POST /api/manage/users - 创建子账号
// PUT /api/manage/users/{username} - 更新子账号
// DELETE /api/manage/users/{username} - 删除子账号
// POST /api/manage/users/{username}?action=toggle - 启用/禁用子账号

import { getDatabase } from '../../../utils/databaseAdapter.js';
import {
    createUser, getUser, updateUser, deleteUser, listUsers
} from '../../../utils/auth/userManager.js';
import { validateSession } from '../../../utils/auth/sessionManager.js';

export async function onRequest(context) {
    const { request, env, params } = context;
    const url = new URL(request.url);
    const db = getDatabase(env);

    // 解析路径参数
    let pathParam = params.path || '';
    if (pathParam) {
        pathParam = decodeURIComponent(pathParam).split(',').join('/');
    }

    try {
        // 无路径参数的路由
        if (!pathParam) {
            // GET /api/manage/users - 列出所有子账号
            if (request.method === 'GET') {
                const action = url.searchParams.get('action');
                if (action === 'self') {
                    return await handleGetSelf(db, env, request);
                }
                return await handleListUsers(db);
            }

            // POST /api/manage/users - 创建子账号
            if (request.method === 'POST') {
                return await handleCreateUser(db, request);
            }

            return jsonRes({ error: 'Method not allowed' }, 405);
        }

        // 有路径参数的路由（pathParam = username）
        const username = pathParam;

        // GET /api/manage/users/{username} - 获取单个子账号信息
        if (request.method === 'GET') {
            return await handleGetUser(db, username);
        }

        // PUT /api/manage/users/{username} - 更新子账号
        if (request.method === 'PUT') {
            return await handleUpdateUser(db, username, request);
        }

        // DELETE /api/manage/users/{username} - 删除子账号
        if (request.method === 'DELETE') {
            return await handleDeleteUser(db, username);
        }

        // POST /api/manage/users/{username}?action=toggle - 启用/禁用
        if (request.method === 'POST') {
            const action = url.searchParams.get('action');
            if (action === 'toggle') {
                return await handleToggleUser(db, username);
            }
            return jsonRes({ error: 'Unsupported action. Use ?action=toggle' }, 400);
        }

        return jsonRes({ error: 'Method not allowed' }, 405);
    } catch (error) {
        console.error('Error in users API:', error);
        return jsonRes({ error: error.message || 'Internal server error' }, 500);
    }
}

/**
 * 获取单个子账号信息
 */
async function handleGetUser(db, username) {
    const user = await getUser(db, username);
    if (!user) {
        return jsonRes({ error: '用户不存在' }, 404);
    }
    return jsonRes(user);
}

/**
 * 列出所有子账号
 */
async function handleListUsers(db) {
    const result = await listUsers(db);
    return jsonRes(result);
}

/**
 * 获取当前用户信息
 */
async function handleGetSelf(db, env, request) {
    // 优先检查 admin session
    let session = await validateSession(env, request, 'admin');
    if (session.valid && session.session) {
        return jsonRes({
            success: true,
            user: {
                username: 'admin',
                displayName: 'admin',
                role: 'admin',
                permissions: ['read', 'upload', 'delete'],
                allowedDirs: ['/'],
            },
        });
    }

    // 检查 user session（子账号）
    session = await validateSession(env, request, 'user');
    if (session.valid && session.session) {
        const username = session.session.username;
        if (username) {
            const user = await getUser(db, username);
            if (user) {
                // 添加 role 标识，便于前端区分
                user.role = 'user';
                return jsonRes({ success: true, user });
            }
        }
    }

    return jsonRes({ error: 'Not authenticated' }, 401);
}

/**
 * 创建子账号
 */
async function handleCreateUser(db, request) {
    const body = await request.json();
    const { username, password, displayName, allowedDirs, quota, permissions, enabled } = body;

    if (!username || !password) {
        return jsonRes({ error: '用户名和密码不能为空' }, 400);
    }

    const result = await createUser(db, {
        username,
        password,
        displayName,
        allowedDirs,
        quota,
        permissions,
        enabled,
    });

    return jsonRes(result, 201);
}

/**
 * 更新子账号（支持部分更新）
 */
async function handleUpdateUser(db, username, request) {
    const body = await request.json();

    if (username === 'admin') {
        return jsonRes({ error: '不能修改 admin 账号' }, 400);
    }

    // 只传递请求体中存在的字段
    const updates = {};
    if (body.displayName !== undefined) updates.displayName = body.displayName;
    if (body.allowedDirs !== undefined) updates.allowedDirs = body.allowedDirs;
    if (body.quota !== undefined) updates.quota = body.quota;
    if (body.permissions !== undefined) updates.permissions = body.permissions;
    if (body.enabled !== undefined) updates.enabled = body.enabled;
    if (body.password !== undefined && body.password !== '') updates.password = body.password;

    const result = await updateUser(db, username, updates);
    return jsonRes(result);
}

/**
 * 删除子账号
 */
async function handleDeleteUser(db, username) {
    try {
        const result = await deleteUser(db, username);
        return jsonRes(result);
    } catch (error) {
        if (error.message.includes('不能删除 admin')) {
            return jsonRes({ error: error.message }, 400);
        }
        if (error.message.includes('用户不存在')) {
            return jsonRes({ error: error.message }, 404);
        }
        throw error;
    }
}

/**
 * 启用/禁用子账号
 */
async function handleToggleUser(db, username) {
    if (username === 'admin') {
        return jsonRes({ error: '不能修改 admin 账号' }, 400);
    }

    const user = await getUser(db, username);
    if (!user) {
        return jsonRes({ error: '用户不存在' }, 404);
    }

    const result = await updateUser(db, username, {
        enabled: !user.enabled,
    });

    return jsonRes({
        success: true,
        username,
        enabled: result.user.enabled,
        message: result.user.enabled ? '用户已启用' : '用户已禁用',
    });
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
