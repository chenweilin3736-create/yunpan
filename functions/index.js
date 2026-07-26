// 根路径重定向到网盘页面
// 访问 ?home 可进入原始图床界面
export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);

    // 带 ?home 参数时,不重定向,直接返回静态首页
    if (url.searchParams.get('home') !== null) {
        return context.next();
    }

    // 根路径重定向到 /netdisk
    if (url.pathname === '/' || url.pathname === '/index.html') {
        return Response.redirect(`${url.origin}/netdisk`, 302);
    }

    // 其他路径正常处理
    return context.next();
}
