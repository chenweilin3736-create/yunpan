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
        return new Response(generateNotFoundPage(shareId), {
            status: 404,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    const share = JSON.parse(data);

    // 检查是否过期
    if (share.expiresAt && Date.now() > share.expiresAt) {
        return new Response(generateExpiredPage(share), {
            status: 410,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    // 检查下载次数限制
    if (share.downloadLimit && share.downloadCount >= share.downloadLimit) {
        return new Response(generateLimitPage(share), {
            status: 410,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }

    const url = new URL(request.url);

    // 如果没有密码,直接重定向到文件下载
    if (!share.password) {
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
            share.downloadCount = (share.downloadCount || 0) + 1;
            await db.put(`manage@share@${shareId}`, JSON.stringify(share));

            const fileUrl = `${url.origin}/file/${encodeURIComponent(share.fileId)}?share=${shareId}`;
            return Response.redirect(fileUrl, 302);
        } else {
            return new Response(generatePasswordPage(share, true, shareId), {
                status: 401,
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
    }

    return new Response(generatePasswordPage(share, false, shareId), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

// ========== 获取文件图标 ==========
function getFileIcon(fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const map = {
        jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', webp: '🖼️', svg: '🖼️', bmp: '🖼️',
        mp4: '🎬', avi: '🎬', mov: '🎬', mkv: '🎬', webm: '🎬',
        mp3: '🎵', wav: '🎵', flac: '🎵', ogg: '🎵',
        pdf: '📕', doc: '📘', docx: '📘', txt: '📄', md: '📄',
        zip: '📦', rar: '📦', '7z': '📦', tar: '📦', gz: '📦',
        xlsx: '📊', xls: '📊', csv: '📊', ppt: '📊', pptx: '📊',
        js: '💻', ts: '💻', json: '💻', html: '💻', css: '💻', py: '💻',
    };
    return map[ext] || '📄';
}

function formatSize(bytes) {
    if (!bytes || bytes === 0) return '未知大小';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(timestamp) {
    if (!timestamp) return '';
    const d = new Date(timestamp);
    return d.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })
        + ' ' + d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
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

// ========== 基础样式 (所有页面共用) ==========
const BASE_STYLE = `
*{margin:0;padding:0;box-sizing:border-box}
body{
  font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','PingFang SC','Microsoft YaHei',sans-serif;
  -webkit-font-smoothing:antialiased;
  min-height:100vh;
  display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,#1e1b4b 0%,#312e81 30%,#4c1d95 70%,#5b21b6 100%);
  background-attachment:fixed;
  padding:1rem;
}
body::before{
  content:'';position:fixed;inset:-50%;
  background:radial-gradient(circle at 30% 20%,rgba(139,92,246,0.25),transparent 45%),
             radial-gradient(circle at 70% 80%,rgba(99,102,241,0.25),transparent 45%);
  animation:bgShift 10s ease-in-out infinite alternate;
  z-index:0;
}
@keyframes bgShift{from{transform:translate(0,0)}to{transform:translate(30px,-20px)}}
.card{
  position:relative;z-index:1;
  background:rgba(255,255,255,0.95);
  backdrop-filter:blur(20px);
  -webkit-backdrop-filter:blur(20px);
  border-radius:24px;
  box-shadow:0 24px 64px rgba(0,0,0,0.25),0 0 0 1px rgba(255,255,255,0.1);
  width:100%;max-width:440px;
  padding:2.5rem 2rem;
  text-align:center;
  animation:cardIn 0.5s cubic-bezier(0.4,0,0.2,1);
}
@keyframes cardIn{from{transform:translateY(20px) scale(0.96);opacity:0}to{transform:translateY(0) scale(1);opacity:1}}
.file-icon{font-size:3.5rem;line-height:1;margin-bottom:0.75rem;display:inline-block;animation:float 3s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.file-name{
  font-size:1.15rem;font-weight:700;color:#1d1d1f;
  margin-bottom:0.5rem;word-break:break-all;
  line-height:1.4;
}
.file-meta{
  font-size:0.85rem;color:#86868b;
  margin-bottom:0.5rem;
  display:flex;align-items:center;justify-content:center;gap:0.8rem;flex-wrap:wrap;
}
.file-meta-item{display:flex;align-items:center;gap:0.3rem}
.file-meta-divider{width:1px;height:14px;background:#d2d2d7}
.password-input{
  width:100%;padding:0.8rem 1rem;
  border:1.5px solid #e5e5e7;
  border-radius:14px;font-size:0.95rem;
  text-align:center;
  transition:all 0.2s;
  background:#fafafa;
  margin-bottom:0.75rem;
  outline:none;
}
.password-input:focus{border-color:#6366f1;background:#fff;box-shadow:0 0 0 4px rgba(99,102,241,0.1)}
.password-input::placeholder{color:#c0c0c5}
.btn-download{
  width:100%;padding:0.85rem;
  background:linear-gradient(135deg,#6366f1,#8b5cf6);
  color:#fff;border:none;border-radius:14px;
  font-size:1rem;font-weight:700;
  cursor:pointer;transition:all 0.2s;
  box-shadow:0 4px 16px rgba(99,102,241,0.35);
  display:inline-flex;align-items:center;justify-content:center;gap:0.5rem;
}
.btn-download:hover{box-shadow:0 6px 22px rgba(99,102,241,0.45);filter:brightness(1.05)}
.btn-download:active{transform:scale(0.97)}
.error-msg{
  color:#ef4444;font-size:0.84rem;
  margin-bottom:0.75rem;
  background:#fef2f2;padding:0.5rem 0.8rem;border-radius:10px;
  animation:shake 0.4s ease;
}
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}
.footer{
  margin-top:1.5rem;font-size:0.75rem;color:#c0c0c5;
  display:flex;align-items:center;justify-content:center;gap:0.35rem;
}
.footer-dot{width:4px;height:4px;border-radius:50%;background:#6366f1;opacity:0.5}
.state-icon{font-size:4rem;margin-bottom:1rem;line-height:1}
.state-title{font-size:1.1rem;font-weight:700;color:#1d1d1f;margin-bottom:0.5rem}
.state-desc{font-size:0.85rem;color:#86868b;margin-bottom:1.5rem;line-height:1.5}

/* 手机端适配 */
@media(max-width:480px){
  .card{padding:2rem 1.25rem;border-radius:20px}
  .file-icon{font-size:3rem}
  .file-name{font-size:1.05rem}
  .password-input{font-size:0.9rem;padding:0.75rem 0.9rem}
  .btn-download{font-size:0.95rem;padding:0.8rem}
}
`;

// ========== 密码输入页 ==========
function generatePasswordPage(share, isError, shareId) {
    const fileName = share.fileName || 'shared file';
    const fileSize = share.fileSizeBytes ? formatSize(share.fileSizeBytes) : (share.fileSize ? share.fileSize + ' MB' : '');
    const createdAt = share.createdAt ? formatDate(share.createdAt) : '';
    const errorHtml = isError ? '<div class="error-msg">密码错误，请重试</div>' : '';

    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>${escapeHtml(fileName)} - 文件分享</title>
<style>${BASE_STYLE}</style>
</head>
<body>
<div class="card">
  <div class="file-icon">${getFileIcon(fileName)}</div>
  <div class="file-name">${escapeHtml(fileName)}</div>
  <div class="file-meta">
    <span class="file-meta-item">📦 ${escapeHtml(fileSize)}</span>
    ${createdAt ? `<span class="file-meta-divider"></span><span class="file-meta-item">📅 ${escapeHtml(createdAt)}</span>` : ''}
  </div>
  ${errorHtml}
  <form method="POST" action="">
    <input type="password" name="password" class="password-input" placeholder="请输入访问密码" autofocus autocomplete="off">
    <button type="submit" class="btn-download">
      <span>🔓</span>验证并下载
    </button>
  </form>
  <div class="footer">
    <span>分享于 我的网盘</span>
    <span class="footer-dot"></span>
    <span>ID: ${escapeHtml(shareId.slice(0,8))}...</span>
  </div>
</div>
</body>
</html>`;
}

// ========== 404 页面 ==========
function generateNotFoundPage(shareId) {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>分享不存在</title>
<style>${BASE_STYLE}</style>
</head>
<body>
<div class="card">
  <div class="state-icon">🔍</div>
  <div class="state-title">分享不存在</div>
  <div class="state-desc">该分享链接可能已被删除<br>或链接地址不正确</div>
  <div class="footer">
    <span>分享于 我的网盘</span>
    <span class="footer-dot"></span>
    <span>ID: ${escapeHtml(shareId.slice(0,8))}...</span>
  </div>
</div>
</body>
</html>`;
}

// ========== 过期页面 ==========
function generateExpiredPage(share) {
    const fileName = share.fileName || 'shared file';
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>分享已过期</title>
<style>${BASE_STYLE}</style>
</head>
<body>
<div class="card">
  <div class="state-icon">⏰</div>
  <div class="state-title">分享已过期</div>
  <div class="state-desc">"${escapeHtml(fileName)}" 的分享链接已超过有效期<br>请联系分享者重新获取</div>
  <div class="footer">
    <span>分享于 我的网盘</span>
  </div>
</div>
</body>
</html>`;
}

// ========== 下载次数用尽页面 ==========
function generateLimitPage(share) {
    const fileName = share.fileName || 'shared file';
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>下载次数已用完</title>
<style>${BASE_STYLE}</style>
</head>
<body>
<div class="card">
  <div class="state-icon">🚫</div>
  <div class="state-title">下载次数已达上限</div>
  <div class="state-desc">"${escapeHtml(fileName)}" 的下载次数已用完<br>请联系分享者重新获取</div>
  <div class="footer">
    <span>分享于 我的网盘</span>
  </div>
</div>
</body>
</html>`;
}