/**
 * TOTP (基于时间的一次性密码) 工具
 * 基于 RFC 6238 实现，使用 Web Crypto API 的 HMAC-SHA1
 * 不依赖任何外部库，兼容 Cloudflare Pages Functions 环境
 */

// RFC 4648 Base32 字母表
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// TOTP 参数
const TIME_STEP = 30;   // 时间窗口（秒）
const CODE_DIGITS = 6;   // TOTP 码位数

// ==================== Base32 编解码 ====================

/**
 * 将字节数组进行 Base32 编码（RFC 4648）
 * @param {Uint8Array} bytes - 待编码的字节数组
 * @returns {string} Base32 编码字符串
 */
function base32Encode(bytes) {
    let result = '';
    let buffer = 0;
    let bitsLeft = 0;

    for (let i = 0; i < bytes.length; i++) {
        buffer = (buffer << 8) | bytes[i];
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            const index = (buffer >>> (bitsLeft - 5)) & 0x1F;
            result += BASE32_ALPHABET[index];
            bitsLeft -= 5;
        }
    }
    // 处理剩余的不足 5 位的部分
    if (bitsLeft > 0) {
        const index = (buffer << (5 - bitsLeft)) & 0x1F;
        result += BASE32_ALPHABET[index];
    }
    return result;
}

/**
 * 将 Base32 字符串解码为字节数组（RFC 4648）
 * 自动处理大小写、空格和填充字符
 * @param {string} str - Base32 编码字符串
 * @returns {Uint8Array} 解码后的字节数组
 */
function base32Decode(str) {
    // 清理输入：转大写，移除非字母表字符（如空格、=、换行）
    const cleaned = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
    const bytes = [];
    let buffer = 0;
    let bitsLeft = 0;

    for (let i = 0; i < cleaned.length; i++) {
        const value = BASE32_ALPHABET.indexOf(cleaned[i]);
        if (value === -1) continue;
        buffer = (buffer << 5) | value;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            bytes.push((buffer >>> (bitsLeft - 8)) & 0xFF);
            bitsLeft -= 8;
        }
    }
    return new Uint8Array(bytes);
}

// ==================== 随机数生成 ====================

/**
 * 生成随机密钥（20 字节，Base32 编码）
 * @returns {string} Base32 编码的密钥字符串
 */
export function generateSecret() {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    return base32Encode(bytes);
}

/**
 * 生成随机 challenge token（用于 2FA 登录流程）
 * @returns {string} 64 位十六进制字符串
 */
export function generateChallengeToken() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ==================== TOTP 生成与验证 ====================

/**
 * 生成 TOTP 码（基于 RFC 6238）
 * @param {string} secret - Base32 编码的密钥
 * @param {number} [timestamp=Date.now()] - 时间戳（毫秒）
 * @returns {Promise<string>} 6 位 TOTP 码
 */
export async function generateTOTP(secret, timestamp = Date.now()) {
    // 计算时间窗口计数器
    const counter = Math.floor(timestamp / 1000 / TIME_STEP);

    // 将密钥从 Base32 解码为字节数组
    const secretBytes = base32Decode(secret);

    // 将计数器转为 8 字节大端序缓冲区
    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    // 高 32 位（实际使用中计数器远小于 2^32，但为完整性处理高位）
    counterView.setUint32(0, Math.floor(counter / 0x100000000));
    // 低 32 位（使用无符号右移确保正确性）
    counterView.setUint32(4, counter >>> 0);

    // 使用 Web Crypto API 计算 HMAC-SHA1
    const key = await crypto.subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );
    const hmacResult = await crypto.subtle.sign('HMAC', key, counterBuffer);
    const hmac = new Uint8Array(hmacResult);

    // 动态截取（Dynamic Truncation，RFC 4226）
    const offset = hmac[hmac.length - 1] & 0x0F;
    const binary =
        ((hmac[offset] & 0x7F) << 24) |
        ((hmac[offset + 1] & 0xFF) << 16) |
        ((hmac[offset + 2] & 0xFF) << 8) |
        (hmac[offset + 3] & 0xFF);

    // 取模得到指定位数的码
    const otp = binary % Math.pow(10, CODE_DIGITS);
    return otp.toString().padStart(CODE_DIGITS, '0');
}

/**
 * 验证 TOTP 码
 * @param {string} secret - Base32 编码的密钥
 * @param {string} token - 用户输入的 TOTP 码
 * @param {number} [window=1] - 允许的时间窗口偏差（±window 个窗口）
 * @returns {Promise<boolean>} 是否验证通过
 */
export async function verifyTOTP(secret, token, window = 1) {
    if (!token || typeof token !== 'string') {
        return false;
    }
    // 标准化输入：去除空格
    const normalizedToken = token.trim().replace(/\s/g, '');

    const now = Date.now();
    for (let i = -window; i <= window; i++) {
        const checkTime = now + i * TIME_STEP * 1000;
        const expected = await generateTOTP(secret, checkTime);
        if (timingSafeEqual(normalizedToken, expected)) {
            return true;
        }
    }
    return false;
}

// ==================== OTPAuth URI ====================

/**
 * 生成 otpauth:// URI（用于二维码扫描）
 * @param {string} secret - Base32 编码的密钥
 * @param {string} accountName - 账号名称
 * @param {string} [issuer='CloudFlare-ImgBed'] - 发行者名称
 * @returns {string} otpauth:// URI
 */
export function generateOTPAuthURI(secret, accountName, issuer = 'CloudFlare-ImgBed') {
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
    const params = new URLSearchParams({
        secret,
        issuer,
        algorithm: 'SHA1',
        digits: CODE_DIGITS.toString(),
        period: TIME_STEP.toString(),
    });
    return `otpauth://totp/${label}?${params.toString()}`;
}

// ==================== 备用码 ====================

/**
 * 生成 10 个一次性备用码（8 位十六进制）
 * @returns {string[]} 包含 10 个备用码的数组
 */
export function generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < 10; i++) {
        const bytes = new Uint8Array(4);
        crypto.getRandomValues(bytes);
        const hex = Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        codes.push(hex);
    }
    return codes;
}

// ==================== 辅助函数 ====================

/**
 * 恒定时间字符串比较，防止时序攻击
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    const encoder = new TextEncoder();
    const bufA = encoder.encode(a);
    const bufB = encoder.encode(b);
    let result = 0;
    for (let i = 0; i < bufA.length; i++) {
        result |= bufA[i] ^ bufB[i];
    }
    return result === 0;
}
