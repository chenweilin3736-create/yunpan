// 临时迁移脚本：把 KV 数据全量灌入 D1
// 用法：访问 /migrate?token=xxx
export async function onRequest(context) {
    const { env, request } = context;
    const url = new URL(request.url);

    if (!env.MIGRATE_TOKEN || url.searchParams.get('token') !== env.MIGRATE_TOKEN) {
        return new Response('Unauthorized', { status: 401 });
    }

    if (!env.img_url || !env.img_d1) {
        const missing = [];
        if (!env.img_url) missing.push('KV(env.img_url)');
        if (!env.img_d1) missing.push('D1(env.img_d1)');
        return new Response(
            '缺少绑定：需要同时绑定 ' + missing.join(' 和 ') + '\n' +
            '请在 Cloudflare Pages → Settings → Bindings 里确认，然后 Retry deployment。',
            { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
        );
    }

    const kv = env.img_url;
    const d1 = env.img_d1;

    const cursor = url.searchParams.get('cursor') || undefined;
    const result = await kv.list({ limit: 500, cursor });

    let processed = 0, skipped = 0;
    const errors = [];

    for (const item of result.keys) {
        try {
            const keyName = item.name;
            const { value, metadata } = await kv.getWithMetadata(keyName);
            const v = value || '';
            const meta = metadata || {};

            if (keyName.startsWith('manage@index@operation_')) {
                const opId = keyName.replace('manage@index@operation_', '');
                let op = {};
                try { op = JSON.parse(v); } catch (e) {}
                await d1.prepare(
                    'INSERT OR REPLACE INTO index_operations (id, type, timestamp, data, processed) VALUES (?, ?, ?, ?, 0)'
                ).bind(opId, op.type || '', op.timestamp || Date.now(), v).run();
            } else if (keyName.startsWith('manage@')) {
                const category = keyName.split('@')[1] || '';
                await d1.prepare(
                    'INSERT OR REPLACE INTO settings (key, value, category) VALUES (?, ?, ?)'
                ).bind(keyName, v, category).run();
            } else {
                const tags = Array.isArray(meta.Tags) ? meta.Tags.join(',') : (meta.Tags || null);
                await d1.prepare(
                    'INSERT OR REPLACE INTO files (' +
                    'id, value, metadata, file_name, file_type, file_size, ' +
                    'upload_ip, upload_address, list_type, timestamp, label, directory, ' +
                    'channel, channel_name, tg_file_id, is_chunked, tags' +
                    ') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
                ).bind(
                    keyName, v, JSON.stringify(meta),
                    meta.FileName || null, meta.FileType || null, meta.FileSize || null,
                    meta.UploadIP || null, meta.UploadAddress || null, meta.ListType || null,
                    meta.TimeStamp || null, meta.Label || null, meta.Directory || null,
                    meta.Channel || null, meta.ChannelName || null, meta.TgFileId || null,
                    meta.IsChunked ? 1 : 0, tags
                ).run();
            }
            processed++;
        } catch (e) {
            errors.push({ key: item.name, error: e.message });
            skipped++;
        }
    }

    return new Response(JSON.stringify({
        processed,
        skipped,
        errors: errors.slice(0, 10),
        total_errors: errors.length,
        hasMore: !result.list_complete,
        nextCursor: result.list_complete ? null : (result.keys[result.keys.length - 1]?.name),
        cursorUsed: cursor || null,
    }, null, 2), {
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
}
