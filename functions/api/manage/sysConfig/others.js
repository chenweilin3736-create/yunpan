import { getDatabase } from '../../../utils/databaseAdapter.js';
import { createApiToken, deleteApiToken } from '../apiTokens.js';

export async function onRequest(context) {
    // 其他设置相关，GET方法读取设置，POST方法保存设置
    const {
      request, // same as existing Worker API
      env, // same as existing Worker API
      params, // if filename includes [id] or [[path]]
      waitUntil, // same as ctx.waitUntil in existing Worker API
      next, // used for middleware or to fetch assets
      data, // arbitrary space for passing data between middlewares
    } = context;

    const db = getDatabase(env);

    // GET读取设置
    if (request.method === 'GET') {
        const settings = await getOthersConfig(db, env)

        return new Response(JSON.stringify(settings), {
            headers: {
                'content-type': 'application/json',
            },
        })
    }

    // POST保存设置
    if (request.method === 'POST') {
        const body = await request.json()
        const settings = body

        // WebDAV internal token 管理
        const webDAV = settings.webDAV || {};
        const oldSettings = await getOthersConfig(db, env);
        const wasEnabled = oldSettings.webDAV?.enabled;
        const isEnabled = webDAV.enabled;

        if (isEnabled && !webDAV.internalToken) {
            // 启用 WebDAV 且没有 token，创建一个 internal 类型的 API Token
            const tokenResult = await createApiToken(
                db,
                'WebDAV Internal Token',
                ['list', 'upload', 'delete'],
                'system',
                null,   // 不过期
                false,  // 不自动删除
                'internal'
            );
            settings.webDAV.internalToken = tokenResult.token;
            settings.webDAV.internalTokenId = tokenResult.id;
        } else if (!isEnabled && oldSettings.webDAV?.internalTokenId) {
            // 禁用 WebDAV，删除 internal token
            await deleteApiToken(db, oldSettings.webDAV.internalTokenId);
            settings.webDAV.internalToken = '';
            settings.webDAV.internalTokenId = '';
        }

        // 写入数据库
        await db.put('manage@sysConfig@others', JSON.stringify(settings))

        return new Response(JSON.stringify(settings), {
            headers: {
                'content-type': 'application/json',
            },
        })
    }

}

export async function getOthersConfig(db, env) {
    const settings = {}
    // 读取数据库中的设置
    const settingsStr = await db.get('manage@sysConfig@others')
    const settingsKV = settingsStr ? JSON.parse(settingsStr) : {}

    // 远端遥测
    const kvTelemetry = settingsKV.telemetry || {}
    settings.telemetry = {
        enabled: kvTelemetry.enabled ?? !(env.disable_telemetry === 'true'),
        fixed: false,
    }

    // 随机图API
    const kvRandomImageAPI = settingsKV.randomImageAPI || {}
    settings.randomImageAPI = {
        enabled: kvRandomImageAPI.enabled ?? env.AllowRandom === 'true',
        allowedDir: kvRandomImageAPI.allowedDir ?? '',
        fixed: false,
    }

    // CloudFlare API Token
    const kvCloudflareApiToken = settingsKV.cloudflareApiToken || {}
    settings.cloudflareApiToken = {
        CF_ZONE_ID: kvCloudflareApiToken.CF_ZONE_ID || env.CF_ZONE_ID,
        CF_EMAIL: kvCloudflareApiToken.CF_EMAIL || env.CF_EMAIL,
        CF_API_KEY: kvCloudflareApiToken.CF_API_KEY || env.CF_API_KEY,
        fixed: false,
    }

    // WebDAV
    const kvWebDAV = settingsKV.webDAV || {}
    settings.webDAV = {
        enabled: kvWebDAV.enabled ?? false,
        username: kvWebDAV.username || '',
        password: kvWebDAV.password || '',
        uploadChannel: kvWebDAV.uploadChannel || '',
        channelName: kvWebDAV.channelName || '',
        internalToken: kvWebDAV.internalToken || '',
        internalTokenId: kvWebDAV.internalTokenId || '',
        fixed: false,
    }

    // 公开浏览
    const kvPublicBrowse = settingsKV.publicBrowse || {}
    settings.publicBrowse = {
        enabled: kvPublicBrowse.enabled ?? false,
        allowedDir: kvPublicBrowse.allowedDir || '',
        fixed: false,
    }

    // 网盘模式开关（启用后关闭图床特有功能：随机图、公开浏览，强化网盘体验）
    const kvNetdiskMode = settingsKV.netdiskMode || {}
    settings.netdiskMode = {
        enabled: kvNetdiskMode.enabled ?? false,
        autoCreateShare: kvNetdiskMode.autoCreateShare ?? false,
        defaultShareExpiry: kvNetdiskMode.defaultShareExpiry ?? 7 * 24 * 3600,
        hideImageTools: kvNetdiskMode.hideImageTools ?? true,
        fixed: false,
    }

    // 端到端加密（E2EE）配置
    // 真正的 E2EE 中，服务器端从不持有用户密钥；此处仅做策略控制
    const kvE2EE = settingsKV.e2ee || {}
    settings.e2ee = {
        // 管理员强制启用：所有上传必须加密（前端校验）
        forceEnabled: kvE2EE.forceEnabled ?? false,
        // 管理员建议默认值：新会话是否默认勾选加密（用户可在前端覆盖）
        defaultEnabled: kvE2EE.defaultEnabled ?? false,
        // 允许用户选择不加密（forceEnabled=true 时此字段无效）
        allowUserOptOut: kvE2EE.allowUserOptOut ?? true,
        // 最小密码长度（前端校验用，服务器端不存密码）
        minPasswordLength: kvE2EE.minPasswordLength ?? 8,
        // 加密算法标识（用于未来算法升级时的向后兼容）
        algorithm: kvE2EE.algorithm ?? 'AES-GCM-256',
        // PBKDF2 迭代次数（前端密钥派生用，影响性能与安全性）
        pbkdf2Iterations: kvE2EE.pbkdf2Iterations ?? 600000,
        fixed: false,
    }

    return settings;
}