import { S3Client, CopyObjectCommand } from "@aws-sdk/client-s3";
import { purgeCFCache, purgeRandomFileListCache, purgePublicFileListCache } from "../../../utils/purgeCache";
import { addFileToIndex } from "../../../utils/indexManager.js";
import { getDatabase } from '../../../utils/databaseAdapter.js';
import { sanitizeUploadFolder } from "../../../upload/uploadTools.js";
import { WebDAVAPI } from "../../../utils/storage/webdavAPI.js";
import {
    resolveS3Credentials,
    resolveWebDAVCredentials,
} from "../../../utils/metadata/channelCredentials.js";
import { cleanPersistedMetadata } from "../../../utils/metadata/metadataSecurity.js";

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

export async function onRequest(context) {
    const { request, env, params, waitUntil } = context;

    // OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: corsHeaders,
        });
    }

    const url = new URL(request.url);

    // 路径参数为源文件 fileId（需要 decodeURIComponent 处理中文等特殊字符）
    const fileId = decodeURIComponent(params.path || '').split(',').join('/');

    if (!fileId) {
        return new Response(JSON.stringify({
            success: false,
            message: 'File ID is required.',
        }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }

    let targetDir = '';

    // GET: 路径参数为源文件 fileId，目标目录从 ?dist= 查询参数读取（与 move 保持一致）
    if (request.method === 'GET') {
        targetDir = sanitizeUploadFolder(url.searchParams.get('dist') || '');
    } else if (request.method === 'POST') {
        // POST: 请求体包含 { targetDir: "目标目录路径" }
        let body;
        try {
            body = await request.json();
        } catch (e) {
            return new Response(JSON.stringify({
                success: false,
                message: 'Invalid request body. Expected JSON.',
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }
        targetDir = sanitizeUploadFolder(body?.targetDir || '');
    } else {
        return new Response(JSON.stringify({
            success: false,
            message: 'Method not allowed. Use GET or POST.',
        }), {
            status: 405,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }

    return await copyFile(context, env, fileId, targetDir, url, waitUntil);
}

// 复制文件的核心函数（保留原文件）
async function copyFile(context, env, fileId, targetDir, url, waitUntil) {
    try {
        const db = getDatabase(env);

        // 获取源文件数据
        const fileData = await db.getWithMetadata(fileId);

        if (!fileData || !fileData.metadata) {
            return new Response(JSON.stringify({
                success: false,
                message: 'File not found.',
            }), {
                status: 404,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 计算新 fileId（保留原文件名，仅替换目录）
        const fileKey = fileId.split('/').pop();
        const newFileId = targetDir === '' ? fileKey : `${targetDir}/${fileKey}`;

        // 不能复制到自身
        if (newFileId === fileId) {
            return new Response(JSON.stringify({
                success: false,
                message: '目标路径与源路径相同。',
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 检查目标 File_ID 是否已存在
        const existingFile = await db.getWithMetadata(newFileId);
        if (existingFile && existingFile.value !== null) {
            return new Response(JSON.stringify({
                success: false,
                message: '目标文件名已存在',
            }), {
                status: 409,
                headers: { 'Content-Type': 'application/json', ...corsHeaders },
            });
        }

        // 复制元数据
        const metadata = { ...fileData.metadata };
        const channel = metadata.Channel;

        // R2 渠道：复制 R2 对象（保留原文件）
        if (channel === 'CloudflareR2') {
            const R2DataBase = env.img_r2;

            // 获取原文件内容
            const object = await R2DataBase.get(fileId);
            if (!object) {
                throw new Error('R2 Object Not Found');
            }

            // 复制到新位置（不删除原文件）
            await R2DataBase.put(newFileId, object.body);
        }

        // S3 渠道：使用 CopyObjectCommand 复制（保留原文件）
        if (channel === 'S3') {
            const { success, newKey, error } = await copyS3File(env, fileData, newFileId);
            if (!success) {
                throw new Error(error || 'S3 Copy Failed');
            }
            metadata.S3FileKey = newKey;
        }

        // WebDAV 渠道：复制文件（保留原文件）
        if (channel === 'WebDAV') {
            const { success, error } = await copyWebDAVFile(env, fileData, newFileId);
            if (!success) {
                throw new Error(error || 'WebDAV Copy Failed');
            }
            metadata.WebDAVFilePath = newFileId;
        }

        // Telegram 渠道（TelegramNew 或 Telegram）：创建新的数据库记录指向相同的 Telegram file_id（元数据复制，不重新上传）
        if (channel === 'TelegramNew' || channel === 'Telegram') {
            if (channel === 'Telegram') {
                // 旧版 Telegram 的 file_id 来自原始 key（file_id + ext），显式记录到元数据
                // 使新记录指向相同的 Telegram file_id
                metadata.TgFileId = fileId.split('.')[0];
            }
            // TelegramNew 的 TgFileId 已存在于 metadata 中，直接保留
        }

        // 不支持的渠道
        if (channel !== 'CloudflareR2' && channel !== 'S3' && channel !== 'WebDAV'
            && channel !== 'TelegramNew' && channel !== 'Telegram') {
            throw new Error('Unsupported Channel');
        }

        // 更新文件夹信息，根目录为空，否则为 aaa/123/ 的格式
        const DirectoryPath = newFileId.split('/').slice(0, -1).join('/') === ''
            ? '' : newFileId.split('/').slice(0, -1).join('/') + '/';
        metadata.Directory = DirectoryPath;
        const cleanedMetadata = cleanPersistedMetadata(metadata);

        // 写入新记录（保留原记录，不删除源文件）
        await db.put(newFileId, fileData.value, { metadata: cleanedMetadata });

        // 清除 CDN 缓存（新文件）
        const cdnUrl = `https://${url.hostname}/file/${newFileId}`;
        await purgeCFCache(env, cdnUrl);

        // 清除 api/randomFileList 等API缓存（目标目录）
        const normalizedDist = newFileId.split('/').slice(0, -1).join('/');
        await purgeRandomFileListCache(url.origin, normalizedDist);
        await purgePublicFileListCache(url.origin, normalizedDist);

        // 更新索引：添加新文件
        waitUntil(addFileToIndex(context, newFileId, cleanedMetadata));

        return new Response(JSON.stringify({
            success: true,
            newFileId,
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });

    } catch (error) {
        console.error('Error copying file:', error);
        return new Response(JSON.stringify({
            success: false,
            message: error.message || 'Internal server error.',
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
}

// 复制 S3 渠道的图片（不删除原文件）
async function copyS3File(env, img, newFileId) {
    const db = getDatabase(env);
    const s3Credentials = await resolveS3Credentials(db, env, img.metadata);
    const s3Client = new S3Client({
        region: s3Credentials.region || "auto",
        endpoint: s3Credentials.endpoint,
        credentials: {
            accessKeyId: s3Credentials.accessKeyId,
            secretAccessKey: s3Credentials.secretAccessKey
        },
        forcePathStyle: s3Credentials.pathStyle || false // 是否启用路径风格
    });

    const bucketName = s3Credentials.bucketName;
    const oldKey = s3Credentials.key;
    const newKey = newFileId;

    try {
        // 复制文件到新位置（不删除原文件）
        await s3Client.send(new CopyObjectCommand({
            Bucket: bucketName,
            CopySource: `/${bucketName}/${oldKey}`,
            Key: newKey,
        }));

        // 返回新的 S3 文件信息
        return {
            success: true,
            newKey,
            endpoint: s3Credentials.endpoint,
            bucketName,
            source: s3Credentials.source
        };
    } catch (error) {
        console.error("S3 Copy Failed:", error);
        return { success: false, error: error.message };
    }
}

// 复制 WebDAV 渠道的图片（不删除原文件）
async function copyWebDAVFile(env, img, newFileId) {
    const oldPath = img.metadata?.WebDAVFilePath;

    if (!oldPath) {
        return { success: false, error: 'WebDAV file missing required metadata for copy' };
    }

    try {
        const db = getDatabase(env);
        const webdavConfig = await resolveWebDAVCredentials(db, env, img.metadata);
        if (!webdavConfig.baseUrl) {
            return { success: false, error: 'WebDAV channel config not found for copy' };
        }

        // 使用 WebDAV COPY 方法复制文件（保留原文件）
        const webdavAPI = new WebDAVAPI(webdavConfig);
        await copyWebDAVObject(webdavAPI, oldPath, newFileId);
        return { success: true, newKey: newFileId, webdavConfig };
    } catch (error) {
        console.error("WebDAV Copy Failed:", error);
        return { success: false, error: error.message };
    }
}

// 使用 WebDAV COPY 方法复制对象（与 MOVE 类似，但不删除源文件）
async function copyWebDAVObject(webdavAPI, oldPath, newPath) {
    // 确保目标目录存在
    await webdavAPI.ensureDirectory(newPath);

    const response = await fetch(webdavAPI.buildObjectUrl(oldPath), {
        method: 'COPY',
        headers: webdavAPI.getRequestHeaders({
            Destination: webdavAPI.buildObjectUrl(newPath),
            Overwrite: 'T',
        }),
        redirect: 'manual',
    });

    if (![200, 201, 204].includes(response.status)) {
        const detail = await response.text().catch(() => '');
        throw new Error(`WebDAV COPY failed: ${response.status} ${response.statusText}${detail ? ` - ${detail}` : ''}`);
    }

    return true;
}
