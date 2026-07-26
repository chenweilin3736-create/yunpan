// 文件分享链接管理 API
// 支持:创建分享、删除分享、获取分享信息、列出所有分享
import { getDatabase } from '../../../utils/databaseAdapter';
import { fetchSecurityConfig } from '../../../utils/sysConfig';

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

export async function onRequest(context) {
    const { request, env, params } = context;

    const path = params.path || '';
    const db = getDatabase(env);

    // POST: 创建分享
    if (request.method === 'POST' && !path) {
        return await createShare(db, request, env);
    }

    // GET: 列出所有分享
    if (request.method === 'GET' && !path) {
        return await listShares(db, env);
    }

    // GET /{shareId}: 获取单个分享信息
    if (request.method === 'GET' && path) {
        return await getShare(db, path, env);
    }

    // DELETE /{shareId}: 删除分享
    if (request.method === 'DELETE' && path) {
        return await deleteShare(db, path, env);
    }

    // PATCH /{shareId}: 更新分享(如延长过期时间)
    if (request.method === 'PATCH' && path) {
        return await updateShare(db, path, request, env);
    }

    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' }
    });
}

// 创建分享链接
async function createShare(db, request, env) {
    try {
        const body = await request.json();
        const { fileId, password, expiresIn, downloadLimit } = body;

        if (!fileId) {
            return new Response(JSON.stringify({ error: 'fileId is required' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 验证文件是否存在
        const fileRecord = await db.getWithMetadata(fileId);
        if (!fileRecord) {
            return new Response(JSON.stringify({ error: 'File not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
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
            createdBy: 'admin',
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
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('Create share failed:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// 列出所有分享
async function listShares(db, env) {
    try {
        const listResponse = await db.list({ prefix: 'manage@share@' });
        const shares = [];

        if (listResponse.keys) {
            for (const key of listResponse.keys) {
                const data = await db.get(key.name);
                if (data) {
                    const share = JSON.parse(data);
                    // 不返回密码
                    shares.push({
                        ...share,
                        password: share.password ? '******' : null,
                    });
                }
            }
        }

        // 按创建时间倒序
        shares.sort((a, b) => b.createdAt - a.createdAt);

        return new Response(JSON.stringify({ shares }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('List shares failed:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// 获取单个分享信息
async function getShare(db, shareId, env) {
    try {
        const data = await db.get(`manage@share@${shareId}`);
        if (!data) {
            return new Response(JSON.stringify({ error: 'Share not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const share = JSON.parse(data);
        share.password = share.password ? '******' : null;

        return new Response(JSON.stringify(share), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('Get share failed:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// 删除分享
async function deleteShare(db, shareId, env) {
    try {
        const data = await db.get(`manage@share@${shareId}`);
        if (!data) {
            return new Response(JSON.stringify({ error: 'Share not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        await db.delete(`manage@share@${shareId}`);

        return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('Delete share failed:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// 更新分享
async function updateShare(db, shareId, request, env) {
    try {
        const data = await db.get(`manage@share@${shareId}`);
        if (!data) {
            return new Response(JSON.stringify({ error: 'Share not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const share = JSON.parse(data);
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

        return new Response(JSON.stringify({
            success: true,
            ...share,
            password: share.password ? '******' : null,
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('Update share failed:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
