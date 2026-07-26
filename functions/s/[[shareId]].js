// 分享链接公开访问入口
// /s/{shareId} - 展示分享信息,验证密码后跳转到文件下载
import { getDatabase } from '../utils/databaseAdapter';

export async function onRequest(context) {
    const { request, env, params } = context;
    const shareId = params.shareId;

    if (!shareId) {
        return new Response('Share not found', { status: 404 });
    }

    const db = getDatabase(env);
    const data = await db.get(`manage@share@${shareId}`);

    if (!data) {
        return new Response(generateNotFoundPage(), {
            status: 404,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    const share = JSON.parse(data);

    // 检查是否过期
    if (share.expiresAt && Date.now() > share.expiresAt) {
        return new Response(generateExpiredPage(), {
            status: 410,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    // 检查下载次数限制
    if (share.downloadLimit && share.downloadCount >= share.downloadLimit) {
        return new Response(generateLimitPage(), {
            status: 410,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    const url = new URL(request.url);

    // 如果没有密码,直接重定向到文件下载
    if (!share.password) {
        // 增加下载计数
        share.downloadCount = (share.downloadCount || 0) + 1;
        await db.put(`manage@share@${shareId}`, JSON.stringify(share));

        const fileUrl = `${url.origin}/file/${encodeURIComponent(share.fileId)}?share=${shareId}`;
        return Response.redirect(fileUrl, 302);
    }

    // 有密码:检查是否已提交密码
    if (request.method === 'POST') {
        const formData = await request.formData();
        const inputPassword = formData.get('password');

        if (inputPassword === share.password) {
            // 密码正确,增加下载计数并重定向
            share.downloadCount = (share.downloadCount || 0) + 1;
            await db.put(`manage@share@${shareId}`, JSON.stringify(share));

            const fileUrl = `${url.origin}/file/${encodeURIComponent(share.fileId)}?share=${shareId}`;
            return Response.redirect(fileUrl, 302);
        } else {
            return new Response(generatePasswordPage(share, true), {
                status: 401,
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
    }

    // GET 请求:展示密码输入页
    return new Response(generatePasswordPage(share, false), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

function generatePasswordPage(share, isError) {
    const fileSizeStr = share.fileSize ? `${share.fileSize} MB` : '';
    const errorMsg = isError ? '<p class="error">密码错误,请重试</p>' : '';
    const fileName = share.fileName || 'shared file';

    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>下载 ${escapeHtml(fileName)}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.card { background: #fff; border-radius: 12px; box-shadow: 0 2px 20px rgba(0,0,0,0.08); padding: 40px; width: 90%; max-width: 420px; text-align: center; }
.icon { font-size: 48px; margin-bottom: 16px; }
h1 { font-size: 18px; color: #333; margin-bottom: 8px; word-break: break-all; }
.file-info { color: #999; font-size: 13px; margin-bottom: 24px; }
input { width: 100%; padding: 12px 16px; border: 1px solid #ddd; border-radius: 6px; font-size: 15px; margin-bottom: 16px; text-align: center; }
input:focus { outline: none; border-color: #4f46e5; }
button { width: 100%; padding: 12px; background: #4f46e5; color: #fff; border: none; border-radius: 6px; font-size: 15px; cursor: pointer; transition: background 0.2s; }
button:hover { background: #4338ca; }
.error { color: #ef4444; font-size: 13px; margin-bottom: 16px; }
.footer { margin-top: 24px; color: #bbb; font-size: 12px; }
</style>
</head>
<body>
<div class="card">
<div class="icon">📦</div>
<h1>${escapeHtml(fileName)}</h1>
<div class="file-info">${escapeHtml(fileSizeStr)}</div>
${errorMsg}
<form method="POST" action="">
<input type="password" name="password" placeholder="输入访问密码" autofocus>
<button type="submit">下载文件</button>
</form>
<div class="footer">Powered by CloudFlare ImgBed</div>
</div>
</body>
</html>`;
}

function generateNotFoundPage() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>分享不存在</title>
<style>
body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f5f7fa; }
.card { text-align: center; padding: 40px; }
.icon { font-size: 64px; }
p { color: #666; margin-top: 16px; }
</style>
</head>
<body><div class="card"><div class="icon">🔍</div><p>分享链接不存在或已被删除</p></div></body>
</html>`;
}

function generateExpiredPage() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>分享已过期</title>
<style>
body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f5f7fa; }
.card { text-align: center; padding: 40px; }
.icon { font-size: 64px; }
p { color: #666; margin-top: 16px; }
</style>
</head>
<body><div class="card"><div class="icon">⏰</div><p>分享链接已过期</p></div></body>
</html>`;
}

function generateLimitPage() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>下载次数已用完</title>
<style>
body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f5f7fa; }
.card { text-align: center; padding: 40px; }
.icon { font-size: 64px; }
p { color: #666; margin-top: 16px; }
</style>
</head>
<body><div class="card"><div class="icon">🚫</div><p>下载次数已达上限</p></div></body>
</html>`;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
