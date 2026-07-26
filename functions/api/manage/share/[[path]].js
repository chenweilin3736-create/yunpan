// 文件分享链接管理 API
// 支持:创建分享、删除分享、获取分享信息、列出所有分享
import { getDatabase } from '../../../utils/databaseAdapter';
import { fetchSecurityConfig } from '../../../utils/sysConfig';
import { validateSession } from '../../../utils/auth/sessionManager.js';
import { getUser } from '../../../utils/auth/userManager.js';

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

// 生成随机分享ID
function generateShareId() {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 生成随机访问密码
function generatePassword(length = 6) {
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

/**
 * 从请求中获取当前认证用户信息（支持 admin 和 user session）
 * 不依赖中间件注入，独立验证 session
 */
async function getCurrentUser(env, request) {
    // 优先检查 admin session
    const adminResult = await validateSession(env, request, 'admin');
    if (adminResult.valid) {
        return { authType: 'admin', username: 'admin', isAdmin: true };
    }

    // 检查 user session（子账号）
    const userResult = await validateSession(env, request, 'user');
    if (userResult.valid && userResult.session?.username) {
        const db = getDatabase(env);
        const userInfo = await getUser(db, userResult.session.username);
        if (userInfo) {
            return {
                authType: 'user',
                username: userResult.session.username,
                isAdmin: false,
                userInfo,
            };
        }
    }

    return null;
}

/**
 * 检查子账号是否有权限访问某文件路径
 */
function checkSubAccountFileAccess(userInfo, fileId) {
    if (!userInfo || !userInfo.allowedDirs) return false;
    const allowedDirs = userInfo.allowedDirs || [];
    const hasFullAccess = allowedDirs.length === 0 || allowedDirs.includes('/');
    if (hasFullAccess) return true;

    // 文件路径是否在授权目录内
    const fileDir = fileId.includes('/') ? fileId.substring(0, fileId.lastIndexOf('/') + 1) : '';
    const normalizedFileDir = fileDir.replace(/^\/+/, '');

    return allowedDirs.some(dir => {
        const normDir = dir.replace(/^\/+|\/+$/g, '');
        if (normDir === '') return true;
        return normalizedFileDir === normDir || normalizedFileDir.startsWith(normDir + '/');
    });
}

export async function onRequest(context) {
    const { request, env, params } = context;

    const path = params.path || '';
    const db = getDatabase(env);

    // OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders });
    }

    // 获取当前用户信息
    const currentUser = await getCurrentUser(env, request);
    if (!currentUser) {
        return jsonRes({ error: '未认证' }, 401);
    }

    // POST: 创建分享
    if (request.method === 'POST' && !path) {
        return await createShare(db, request, env, currentUser);
    }

    // GET: 列出分享（按用户隔离）
    if (request.method === 'GET' && !path) {
        return await listShares(db, env, currentUser);
    }

    // GET /{shareId}: 获取单个分享信息
    if (request.method === 'GET' && path) {
        return await getShare(db, path, env, currentUser);
    }

    // DELETE /{shareId}: 删除分享
    if (request.method === 'DELETE' && path) {
        return await deleteShare(db, path, env, currentUser);
    }

    // PATCH /{shareId}: 更新分享(如延长过期时间)
    if (request.method === 'PATCH' && path) {
        return await updateShare(db, path, request, env, currentUser);
    }

    return jsonRes({ error: 'Method not allowed' }, 405);
}

// 创建分享链接
async function createShare(db, request, env, currentUser) {
    try {
        const body = await request.json();
        const { fileId, password, expiresIn, downloadLimit } = body;

        if (!fileId) {
            return jsonRes({ error: 'fileId is required' }, 400);
        }

        // 子账号：检查是否有权限分享该文件
        if (!currentUser.isAdmin) {
            if (!checkSubAccountFileAccess(currentUser.userInfo, fileId)) {
                return jsonRes({ error: '无权分享该文件' }, 403);
            }
        }

        // 验证文件是否存在
        const fileRecord = await db.getWithMetadata(fileId);
        if (!fileRecord) {
            return jsonRes({ error: 'File not found' }, 404);
        }

        const shareId = generateShareId();
        const now = Date.now();

        // 计算过期时间(expiresIn 单位为秒,不传则永久)
        let expiresAt = null;
        if (expiresIn && expiresIn > 0) {
            expiresAt = now + expiresIn * 1000;
        }

        const shareData = {
            shareId,
            fileId,
            fileName: fileRecord.metadata?.FileName || fileId.split('/').pop(),
            fileType: fileRecord.metadata?.FileType || 'application/octet-stream',
            fileSize: fileRecord.metadata?.FileSize || null,
            password: password || null,
            expiresAt,
            downloadLimit: downloadLimit || null,
            downloadCount: 0,
            createdAt: now,
            createdBy: currentUser.username,
            createdByType: currentUser.authType,
        };

        // 存储分享记录
        await db.put(`manage@share@${shareId}`, JSON.stringify(shareData));

        // 构建分享链接
        const url = new URL(request.url);
        const shareUrl = `${url.origin}/s/${shareId}`;

        return new Response(JSON.stringify({
            success: true,
            shareId,
            shareUrl,
            ...shareData,
            password: password ? password : undefined, // 返回明文密码(仅创建时)
        }), {
            status: 201,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        console.error('Create share failed:', error);
        return jsonRes({ error: error.message }, 500);
    }
}

// 列出分享（按用户隔离）
async function listShares(db, env, currentUser) {
    try {
        const listResponse = await db.list({ prefix: 'manage@share@' });
        const shares = [];

        if (listResponse.keys) {
            for (const key of listResponse.keys) {
                const data = await db.get(key.name);
                if (data) {
                    try {
                        const share = JSON.parse(data);

                        // 子账号：只能看到自己创建的分享，且文件在授权目录内
                        if (!currentUser.isAdmin) {
                            if (share.createdBy !== currentUser.username) {
                                continue; // 跳过其他用户的分享
                            }
                            if (!checkSubAccountFileAccess(currentUser.userInfo, share.fileId)) {
                                continue; // 跳过授权目录外的分享
                            }
                        }

                        // 不返回密码
                        shares.push({
                            ...share,
                            password: share.password ? '******' : null,
                        });
                    } catch (e) {
                        console.error('Failed to parse share:', e);
                    }
                }
            }
        }

        // 按创建时间倒序
        shares.sort((a, b) => b.createdAt - a.createdAt);

        return jsonRes({ shares });
    } catch (error) {
        console.error('List shares failed:', error);
        return jsonRes({ error: error.message }, 500);
    }
}

// 获取单个分享信息
async function getShare(db, shareId, env, currentUser) {
    try {
        const data = await db.get(`manage@share@${shareId}`);
        if (!data) {
            return jsonRes({ error: 'Share not found' }, 404);
        }

        const share = JSON.parse(data);

        // 子账号：只能查看自己的分享
        if (!currentUser.isAdmin) {
            if (share.createdBy !== currentUser.username) {
                return jsonRes({ error: '无权查看该分享' }, 403);
            }
            if (!checkSubAccountFileAccess(currentUser.userInfo, share.fileId)) {
                return jsonRes({ error: '无权查看该分享' }, 403);
            }
        }

        share.password = share.password ? '******' : null;

        return jsonRes(share);
    } catch (error) {
        console.error('Get share failed:', error);
        return jsonRes({ error: error.message }, 500);
    }
}

// 删除分享
async function deleteShare(db, shareId, env, currentUser) {
    try {
        const data = await db.get(`manage@share@${shareId}`);
        if (!data) {
            return jsonRes({ error: 'Share not found' }, 404);
        }

        const share = JSON.parse(data);

        // 子账号：只能删除自己的分享
        if (!currentUser.isAdmin) {
            if (share.createdBy !== currentUser.username) {
                return jsonRes({ error: '无权删除该分享' }, 403);
            }
        }

        await db.delete(`manage@share@${shareId}`);

        return jsonRes({ success: true });
    } catch (error) {
        console.error('Delete share failed:', error);
        return jsonRes({ error: error.message }, 500);
    }
}

// 更新分享
async function updateShare(db, shareId, request, env, currentUser) {
    try {
        const data = await db.get(`manage@share@${shareId}`);
        if (!data) {
            return jsonRes({ error: 'Share not found' }, 404);
        }

        const share = JSON.parse(data);

        // 子账号：只能更新自己的分享
        if (!currentUser.isAdmin) {
            if (share.createdBy !== currentUser.username) {
                return jsonRes({ error: '无权更新该分享' }, 403);
            }
        }

        const body = await request.json();

        // 支持更新过期时间、密码、下载限制
        if (body.expiresIn !== undefined) {
            share.expiresAt = body.expiresIn > 0 ? Date.now() + body.expiresIn * 1000 : null;
        }
        if (body.password !== undefined) {
            share.password = body.password || null;
        }
        if (body.downloadLimit !== undefined) {
            share.downloadLimit = body.downloadLimit || null;
        }

        await db.put(`manage@share@${shareId}`, JSON.stringify(share));

        return jsonRes({
            success: true,
            ...share,
            password: share.password ? '******' : null,
        });
    } catch (error) {
        console.error('Update share failed:', error);
        return jsonRes({ error: error.message }, 500);
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
            ...corsHeaders,
        },
    });
}
