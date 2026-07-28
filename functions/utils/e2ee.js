/**
 * ============================================================
 * 端到端加密（E2EE）后端辅助工具模块
 * ============================================================
 * 【安全设计原则】真正的 E2EE 中，服务器端 NEVER 持有用户的加密密钥。
 * 所有对称加密（AES-GCM）和密钥派生（PBKDF2）均在前端浏览器内完成。
 *
 * 此模块负责：
 *   1. 配置读取与策略决策（是否强制 E2EE、默认值等）
 *   2. 上传元数据校验（前端加密后提交的元数据格式检查）
 *   3. Cover Set 计算（基于目录/用户授权模型，决定 fileKey 需要被哪些
 *     路径密钥加密后保存，用于支持"子账户仅访问特定目录"场景）
 *   4. metadata 字段标准化（写入数据库前的 E2EE 字段清理/校验）
 *   5. 下载侧的响应头打标（告知前端响应体是密文，需解密）
 * ============================================================
 */

import { fetchOthersConfig } from './sysConfig.js';

/* ============================================================
 * 1. 配置与策略
 * ==========================================================*/

/**
 * 获取 E2EE 配置（安全默认值兜底）
 * @param {Object} env - Cloudflare env 对象
 * @returns {Promise<Object>} e2ee 配置对象
 */
export async function getE2EEConfig(env) {
  try {
    const others = await fetchOthersConfig(env);
    return others.e2ee || {
      forceEnabled: false,
      defaultEnabled: false,
      allowUserOptOut: true,
      minPasswordLength: 8,
      algorithm: 'AES-GCM-256',
      pbkdf2Iterations: 600000,
    };
  } catch (e) {
    console.error('[E2EE] Failed to fetch config, using safe defaults:', e.message);
    return {
      forceEnabled: false,
      defaultEnabled: false,
      allowUserOptOut: true,
      minPasswordLength: 8,
      algorithm: 'AES-GCM-256',
      pbkdf2Iterations: 600000,
    };
  }
}

/**
 * 检查是否应该对本次上传应用 E2EE 策略（仅用于服务端二次校验，真正加解密由前端完成）
 * @param {Object} env - env
 * @param {Object} clientHints - 客户端提交的 hints（formData 中带的 e2ee 字段）
 * @returns {Promise<{enforced: boolean, recommended: boolean, config: Object}>}
 *   - enforced: true 表示管理员强制加密，服务端应拒绝不带加密元数据的上传
 *   - recommended: true 表示建议加密（用户可选择）
 */
export async function resolveE2EEPolicy(env, clientHints = {}) {
  const config = await getE2EEConfig(env);
  const clientEnabled = clientHints?.e2eeEnabled === 'true' || clientHints?.e2eeEnabled === true;
  const enforced = !!config.forceEnabled;

  // 如果管理员强制，客户端必须已加密
  if (enforced && !clientEnabled) {
    return { enforced: true, recommended: true, clientEnabled: false, config, valid: false };
  }

  return {
    enforced,
    recommended: enforced || !!config.defaultEnabled,
    clientEnabled,
    config,
    valid: true,
  };
}

/* ============================================================
 * 2. 上传元数据校验与标准化
 * ==========================================================*/

const ALLOWED_ENCRYPTION_ALGOS = new Set(['AES-GCM-256', 'AES-GCM-128', 'XCHACHA20-POLY1305']);

/**
 * 校验前端提交的加密元数据是否完整、合法
 * （服务器不持有密钥，所以无法验证密文正确性；仅做格式与语义校验）
 *
 * @param {Object} clientMeta - 前端随上传提交的加密相关字段（从 formData 提取）
 * @param {Object} policy - resolveE2EEPolicy 返回值
 * @returns {{ ok: boolean, error?: string, cleaned?: Object }}
 */
export function validateE2EEMetadata(clientMeta = {}, policy = {}) {
  // 非加密上传直接通过
  if (!policy.clientEnabled && !policy.enforced) {
    return { ok: true };
  }
  if (policy.enforced && !policy.clientEnabled) {
    return { ok: false, error: '管理员已强制启用端到端加密，请在前端开启 E2EE 后再上传' };
  }

  const algo = clientMeta.e2eeAlgorithm;
  if (!algo || !ALLOWED_ENCRYPTION_ALGOS.has(algo)) {
    return { ok: false, error: `不支持的加密算法：${algo || '(未提供)'}` };
  }

  // 原文件信息（加密后 Content-Type 会变成 application/octet-stream，需保存原始值）
  if (policy.clientEnabled && !clientMeta.e2eeOriginalFileType) {
    return { ok: false, error: '加密上传缺少 e2eeOriginalFileType（原始 Content-Type）' };
  }
  if (policy.clientEnabled && !clientMeta.e2eeOriginalFileName) {
    return { ok: false, error: '加密上传缺少 e2eeOriginalFileName（原始文件名）' };
  }

  // IV 长度校验（AES-GCM 标准 12 字节）
  if (algo.startsWith('AES-GCM') && clientMeta.e2eeIvBase64) {
    try {
      const ivBytes = atob(clientMeta.e2eeIvBase64);
      if (ivBytes.length !== 12) {
        return { ok: false, error: 'AES-GCM IV 必须为 12 字节（96 位）' };
      }
    } catch (_) {
      return { ok: false, error: 'e2eeIvBase64 不是合法 Base64' };
    }
  }

  // Salt 长度（PBKDF2 推荐 16 字节以上）
  if (clientMeta.e2eeSaltBase64) {
    try {
      const saltBytes = atob(clientMeta.e2eeSaltBase64);
      if (saltBytes.length < 8) {
        return { ok: false, error: 'PBKDF2 salt 至少需要 8 字节' };
      }
    } catch (_) {
      return { ok: false, error: 'e2eeSaltBase64 不是合法 Base64' };
    }
  }

  // 清理并返回标准化后的字段
  const cleaned = {
    Encrypted: true,
    EncryptionAlgo: algo,
    OriginalFileType: String(clientMeta.e2eeOriginalFileType),
    OriginalFileName: String(clientMeta.e2eeOriginalFileName),
    // 可选：PBKDF2 迭代次数 & salt（可公开，不敏感，用于未来同一密码重新派生）
    PBKDF2Iterations: clientMeta.e2eeIterations ? Number(clientMeta.e2eeIterations) : undefined,
    SaltBase64: clientMeta.e2eeSaltBase64 || undefined,
    // 可选：IV（也存储一份方便校验，但密文前缀通常已经包含 IV）
    IvBase64: clientMeta.e2eeIvBase64 || undefined,
    // 可选：密钥版本 / KID（用于用户更换密码后的密钥轮转）
    KeyVersion: clientMeta.e2eeKeyVersion ? String(clientMeta.e2eeKeyVersion) : 'v1',
    // 可选：Cover Set 加密的 fileKey 列表（JSON 字符串或对象均可）
    // 格式：{ [pathSegment]: base64(wrappedFileKey) }，根路径使用 ""
    EncryptedKeys: normalizeEncryptedKeys(clientMeta.e2eeEncryptedKeys),
  };

  // 移除 undefined 字段，减少元数据体积
  for (const k of Object.keys(cleaned)) {
    if (cleaned[k] === undefined) delete cleaned[k];
  }

  return { ok: true, cleaned };
}

function normalizeEncryptedKeys(raw) {
  if (!raw) return undefined;
  try {
    const obj = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (typeof obj !== 'object' || Array.isArray(obj)) return undefined;
    // 仅保留值为非空字符串的条目
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string' && v.length > 0) {
        // 规范化路径键：去除前后斜杠，根用空字符串
        const key = String(k).replace(/^\/+|\/+$/g, '');
        out[key] = v;
      }
    }
    return Object.keys(out).length > 0 ? out : undefined;
  } catch (_) {
    return undefined;
  }
}

/* ============================================================
 * 3. Cover Set 计算（目录授权模型）
 * ==========================================================*/

/**
 * 计算一个文件所属目录的"覆盖集（Cover Set）"。
 * 覆盖集是文件需要被加密存储的路径集合：从文件所在目录向上回溯到根，
 * 每个目录节点都代表一个可能的授权边界。例如子账户被授予访问 "/photos"
 * 则其解密密钥能解开 "/photos/**" 下所有文件。
 *
 * 【典型结果示例】
 *   - 文件路径 "albums/2024/summer/beach.jpg"
 *   - 覆盖集 = ["albums/2024/summer", "albums/2024", "albums", ""]
 *
 * @param {string} directory - 归一化后的目录（不含末尾文件名；可为空代表根）
 * @returns {string[]} 按"最深 → 根"顺序排列的路径集合（最后一个是空串即根节点）
 */
export function calculateCoverSet(directory = '') {
  const normalized = String(directory || '').replace(/^\/+|\/+$/g, '');
  if (!normalized) return [''];

  const segments = normalized.split('/').filter(Boolean);
  const result = [];
  for (let i = segments.length; i >= 1; i--) {
    result.push(segments.slice(0, i).join('/'));
  }
  result.push(''); // 根节点
  return result;
}

/**
 * 在下载侧，对当前用户可访问的目录权限，计算其可用的查找路径集合
 * （和 calculateCoverSet 对称；用于在 encryptedKeys 中查找匹配条目）
 *
 * @param {string} userAccessibleDir - 用户可访问的目录（如 "/photos/2024"）
 * @param {string} fileDir - 文件实际所在目录
 * @returns {string[]} 可能命中的查找键（按优先级排序，越长越精确越靠前）
 */
export function calculateDecryptionLookupSet(userAccessibleDir = '', fileDir = '') {
  const normUser = String(userAccessibleDir || '').replace(/^\/+|\/+$/g, '');
  const normFile = String(fileDir || '').replace(/^\/+|\/+$/g, '');

  // 如果用户授权目录不是文件目录的前缀，返回空（表示无交集，无法解密）
  if (normUser && !normFile.startsWith(normUser + '/') && normFile !== normUser) {
    return [];
  }

  // 从文件目录向上回溯，到用户目录截止（再往上的目录用户无权）
  const fileSegments = normFile ? normFile.split('/') : [];
  const userSegments = normUser ? normUser.split('/') : [];

  const set = [];
  for (let i = fileSegments.length; i >= userSegments.length; i--) {
    set.push(fileSegments.slice(0, i).join('/'));
  }
  // 用户目录以下部分已经在循环中加入；若用户目录是空串则根节点""必须在末尾
  if (!normUser && set[set.length - 1] !== '') {
    set.push('');
  }
  return set;
}

/* ============================================================
 * 4. metadata 合并工具：在写入数据库前标准化 E2EE 字段
 * ==========================================================*/

/**
 * 将客户端提交的 E2EE 字段合并进 metadata，并做必要的校验。
 * 调用方应在各渠道 upload 函数中使用此函数。
 *
 * @param {Object} metadata - 当前将要写入的 metadata 对象
 * @param {Object} formDataE2EEFields - 从 formData 中提取出的 e2ee* 字段
 * @param {Object} policy - resolveE2EEPolicy 结果
 * @returns {Promise<{ ok: boolean, error?: string, metadata?: Object }>}
 */
export async function applyE2EEToMetadata(metadata, formDataE2EEFields, policy) {
  if (!policy.clientEnabled && !policy.enforced) {
    // 非加密上传：清除潜在的旧 E2EE 字段（如果有），避免混淆
    const copy = { ...metadata };
    delete copy.Encrypted;
    delete copy.EncryptionAlgo;
    delete copy.OriginalFileType;
    delete copy.OriginalFileName;
    delete copy.PBKDF2Iterations;
    delete copy.SaltBase64;
    delete copy.IvBase64;
    delete copy.KeyVersion;
    delete copy.EncryptedKeys;
    return { ok: true, metadata: copy };
  }

  const validation = validateE2EEMetadata(formDataE2EEFields, policy);
  if (!validation.ok) {
    return { ok: false, error: validation.error };
  }

  return {
    ok: true,
    metadata: {
      ...metadata,
      ...validation.cleaned,
      // 注意：加密后 FileSize/FileType 反映的是密文大小和类型；
      // 但保留原类型在 OriginalFileType 中便于前端解密后还原显示
    },
  };
}

/**
 * 便捷函数：从 FormData 中一次性提取所有 E2EE 相关字段
 * @param {FormData} formData
 * @returns {Object} 扁平字段对象
 */
export function extractE2EEFields(formData) {
  if (!formData || typeof formData.get !== 'function') return {};
  const keys = [
    'e2eeEnabled',
    'e2eeAlgorithm',
    'e2eeOriginalFileType',
    'e2eeOriginalFileName',
    'e2eeIvBase64',
    'e2eeSaltBase64',
    'e2eeIterations',
    'e2eeKeyVersion',
    'e2eeEncryptedKeys',
  ];
  const out = {};
  for (const k of keys) {
    const v = formData.get(k);
    if (v !== null && v !== undefined && v !== '') {
      out[k] = v;
    }
  }
  return out;
}

/* ============================================================
 * 5. 下载侧响应头打标
 * ==========================================================*/

/**
 * 在下载响应头中添加 E2EE 标记，告知前端：
 *   X-File-Encrypted: 1              -> 该响应体是密文
 *   X-File-Algorithm: AES-GCM-256     -> 算法
 *   X-File-Original-Name: ...         -> 原始文件名（已 encodeURIComponent）
 *   X-File-Original-Type: ...         -> 原始 Content-Type
 *   X-File-Salt: <base64>             -> PBKDF2 salt（若存了的话）
 *   X-File-Iterations: <number>       -> PBKDF2 迭代次数
 *   X-File-Key-Version: v1            -> 密钥版本
 *   X-File-Iv: <base64>               -> IV（若密文前缀没带 IV 时使用）
 *   X-File-Dir: <normalizedDir>       -> 文件目录，前端用于查找解密 key
 *
 * 调用方在构造 Response 前合并这些 header 即可。
 *
 * @param {Object} metadata - 文件的 metadata
 * @returns {Record<string,string>} 需要追加到响应的头部（值均为字符串）
 */
export function buildE2EEResponseHeaders(metadata = {}) {
  if (!metadata.Encrypted) return {};

  const headers = {};
  headers['X-File-Encrypted'] = '1';
  if (metadata.EncryptionAlgo) headers['X-File-Algorithm'] = String(metadata.EncryptionAlgo);
  if (metadata.OriginalFileType) headers['X-File-Original-Type'] = String(metadata.OriginalFileType);
  if (metadata.OriginalFileName) {
    try {
      headers['X-File-Original-Name'] = encodeURIComponent(String(metadata.OriginalFileName));
    } catch (_) { /* noop */ }
  }
  if (metadata.SaltBase64) headers['X-File-Salt'] = String(metadata.SaltBase64);
  if (metadata.PBKDF2Iterations) headers['X-File-Iterations'] = String(metadata.PBKDF2Iterations);
  if (metadata.KeyVersion) headers['X-File-Key-Version'] = String(metadata.KeyVersion);
  if (metadata.IvBase64) headers['X-File-Iv'] = String(metadata.IvBase64);
  if (metadata.Directory !== undefined) headers['X-File-Dir'] = String(metadata.Directory);
  // 如果有 EncryptedKeys 条目数标记，前端可据此判断是否已按目录授权分发
  if (metadata.EncryptedKeys && typeof metadata.EncryptedKeys === 'object') {
    headers['X-File-Key-Wraps'] = String(Object.keys(metadata.EncryptedKeys).length);
  }
  return headers;
}

/**
 * 辅助：在 metadata 中查找当前用户能命中的 encryptedKey 条目（仅用于后端日志/调试，
 * 真实解密发生在前端）。返回命中的路径键，或 null。
 */
export function findAuthorizedEncryptedKey(metadata = {}, userDir = '') {
  if (!metadata.Encrypted || !metadata.EncryptedKeys) return null;
  const fileDir = String(metadata.Directory || '').replace(/^\/+|\/+$/g, '');
  const lookups = calculateDecryptionLookupSet(userDir, fileDir);
  for (const k of lookups) {
    if (metadata.EncryptedKeys[k]) return k;
  }
  return null;
}
