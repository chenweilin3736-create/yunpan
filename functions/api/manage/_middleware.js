import { authenticate, AUTH_SCOPE } from "../../utils/auth/authCore.js";
import { getUser } from "../../utils/auth/userManager.js";
import { getDatabase } from "../../utils/databaseAdapter.js";

const DEFAULT_MANAGE_CACHE_CONTROL = 'private, no-store, max-age=0';

function withDefaultCacheControl(response) {
  if (response.headers.has('Cache-Control')) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.set('Cache-Control', DEFAULT_MANAGE_CACHE_CONTROL);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function errorHandling(context) {
  try {
    return withDefaultCacheControl(await context.next());
  } catch (err) {
    return new Response(`${err.message}\n${err.stack}`, {
      status: 500,
      headers: {
        'Cache-Control': DEFAULT_MANAGE_CACHE_CONTROL,
      },
    });
  }
}

function UnauthorizedException(reason) {
  return new Response(reason, {
    status: 401,
    statusText: 'Unauthorized',
    headers: {
      'Content-Type': 'text/plain;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Content-Length': reason.length,
    },
  });
}

/**
 * 根据请求路径提取所需权限
 * @param {string} pathname - 请求路径
 * @returns {string} 需要的权限类型
 */
function extractRequiredPermission(pathname) {
  const pathParts = pathname.toLowerCase().split('/');

  if (pathParts.includes('delete')) {
    return 'delete';
  }

  if (pathParts.includes('list')) {
    return 'list';
  }

  // 其他 /api/manage 下的操作需要管理权限
  return 'manage';
}

// CORS 跨域响应头
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT, PATCH, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

async function authentication(context) {
  // OPTIONS 预检请求不需要鉴权，直接返回 CORS 响应
  if (context.request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }

  const requestUrl = new URL(context.request.url);
  const pathname = requestUrl.pathname;

  // 2FA 验证端点使用 challenge token 认证，不需要 session
  // 仅当 action=verify 作为查询参数传递时跳过认证
  if (pathname.startsWith('/api/manage/2fa') && requestUrl.searchParams.get('action') === 'verify') {
    return context.next();
  }

  const requiredPermission = extractRequiredPermission(pathname);

  const result = await authenticate({
    env: context.env,
    request: context.request,
    requiredPermission,
    authScope: AUTH_SCOPE.EITHER,
  });

  if (!result.authorized) {
    return UnauthorizedException('You need to login');
  }

  // 注入用户身份信息到 context，供下游 API 使用
  context.authType = result.authType; // 'admin' | 'user'
  context.authSession = result.session; // session 对象（含 username）

  // 如果是子账号（user session），加载完整用户信息用于权限控制
  if (result.authType === 'user' && result.session?.username) {
    try {
      const db = getDatabase(context.env);
      const userInfo = await getUser(db, result.session.username);
      if (userInfo) {
        context.currentUser = userInfo;

        // 子账号功能限制：某些管理端 API 仅限管理员访问
        const requestUrl = new URL(context.request.url);
        const pathname = requestUrl.pathname.toLowerCase();
        const action = requestUrl.searchParams.get('action');
        // 子账号可以访问 /api/manage/users?action=self 获取自身信息
        const isAdminOnlyPath = pathname.startsWith('/api/manage/users') && action !== 'self';
        const adminOnlyPaths = ['/api/manage/logs', '/api/manage/stats', '/api/manage/sysconfig', '/api/manage/apitokens', '/api/manage/cusconfig'];
        const isAdminOnly = isAdminOnlyPath || adminOnlyPaths.some(p => pathname.startsWith(p));
        if (isAdminOnly) {
          return new Response(JSON.stringify({ error: '权限不足：仅管理员可访问此功能' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
          });
        }

        // 子账号操作权限检查
        const method = context.request.method;
        // 会话管理 API 不受删除权限限制（会话销毁不属于文件删除操作）
        const isSessionMgmt = pathname.startsWith('/api/manage/sessions');
        if (method === 'DELETE' && !isSessionMgmt && !userInfo.permissions?.includes('delete')) {
          return new Response(JSON.stringify({ error: '权限不足：无删除权限' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
          });
        }
        if (method === 'POST' && pathname.includes('/upload') && !userInfo.permissions?.includes('upload')) {
          return new Response(JSON.stringify({ error: '权限不足：无上传权限' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
          });
        }
      } else {
        // 用户已被删除，拒绝访问
        return UnauthorizedException('Account no longer exists');
      }
    } catch (e) {
      console.error('Failed to load user info in middleware:', e);
    }
  }

  return context.next();
}

export const onRequest = [errorHandling, authentication];
