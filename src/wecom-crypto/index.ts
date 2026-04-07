/**
 * WeCom 加解密通用核心
 * 独立于 Webhook、WebSocket、Agent 的具体协议形态，统一提供基于 AES-256-CBC 
 * 的加解密与 SHA1 签名计算能力。
 */

import crypto from "node:crypto";

const CRYPTO_CONSTANTS = {
    /** PKCS#7 块大小 */
    PKCS7_BLOCK_SIZE: 32,
    /** AES Key 长度 */
    AES_KEY_LENGTH: 32,
} as const;

/**
 * 解码企业微信提供的 Base64 encodingAESKey
 */
export function decodeEncodingAESKey(encodingAESKey: string): Buffer {
    const trimmed = encodingAESKey.trim();
    if (!trimmed) throw new Error("encodingAESKey missing");
    const withPadding = trimmed.endsWith("=") ? trimmed : `${trimmed}=`;
    const key = Buffer.from(withPadding, "base64");
    if (key.length !== CRYPTO_CONSTANTS.AES_KEY_LENGTH) {
        throw new Error(`invalid encodingAESKey (expected ${CRYPTO_CONSTANTS.AES_KEY_LENGTH} bytes, got ${key.length})`);
    }
    return key;
}

/**
 * PKCS#7 填充
 */
export function pkcs7Pad(buf: Buffer, blockSize: number): Buffer {
    const mod = buf.length % blockSize;
    const pad = mod === 0 ? blockSize : blockSize - mod;
    const padByte = Buffer.alloc(1, pad);
    return Buffer.concat([buf, Buffer.alloc(pad, padByte[0])]);
}

/**
 * PKCS#7 解除填充
 */
export function pkcs7Unpad(buf: Buffer, blockSize: number): Buffer {
    if (buf.length === 0) throw new Error("invalid pkcs7 payload");
    const pad = buf[buf.length - 1];
    if (pad < 1 || pad > blockSize) {
        throw new Error("invalid pkcs7 padding value");
    }
    if (pad > buf.length) {
        throw new Error("invalid pkcs7 payload length");
    }
    for (let i = 0; i < pad; i += 1) {
        if (buf[buf.length - 1 - i] !== pad) {
            throw new Error("invalid pkcs7 padding byte");
        }
    }
    return buf.subarray(0, buf.length - pad);
}

/**
 * 计算 SHA1 哈希
 */
function sha1Hex(input: string): string {
    return crypto.createHash("sha1").update(input).digest("hex");
}

export class WecomCrypto {
    private aesKey: Buffer;
    private iv: Buffer;

    constructor(
        private token: string,
        private encodingAESKey: string,
        private receiveId?: string // 对应企业微信的 corpId 或 botId (用于校验与追加)
    ) {
        if (!token) throw new Error("token is required");
        this.aesKey = decodeEncodingAESKey(encodingAESKey);
        this.iv = this.aesKey.subarray(0, 16);
    }

    /**
     * 计算 WeCom 消息签名
     */
    public computeSignature(timestamp: string, nonce: string, encrypt: string): string {
        const parts = [this.token, timestamp, nonce, encrypt]
            .map((v) => String(v ?? ""))
            .sort();
        return sha1Hex(parts.join(""));
    }

    /**
     * 验证 WeCom 消息签名
     */
    public verifySignature(signature: string, timestamp: string, nonce: string, encrypt: string): boolean {
        const expected = this.computeSignature(timestamp, nonce, encrypt);
        return expected === signature;
    }

    /**
     * 消息解密
     * 返回纯文本字符串（XML 或 JSON 根据上层业务而定）
     */
    public decrypt(encryptText: string): string {
        const decipher = crypto.createDecipheriv("aes-256-cbc", this.aesKey, this.iv);
        decipher.setAutoPadding(false);
        const decryptedPadded = Buffer.concat([
            decipher.update(Buffer.from(encryptText, "base64")),
            decipher.final(),
        ]);
        const decrypted = pkcs7Unpad(decryptedPadded, CRYPTO_CONSTANTS.PKCS7_BLOCK_SIZE);

        if (decrypted.length < 20) {
            throw new Error(`invalid payload (expected >=20 bytes, got ${decrypted.length})`);
        }

        // 16 bytes random + 4 bytes length + msg + receiveId
        const msgLen = decrypted.readUInt32BE(16);
        const msgStart = 20;
        const msgEnd = msgStart + msgLen;
        if (msgEnd > decrypted.length) {
            throw new Error(`invalid msg length (msgEnd=${msgEnd}, total=${decrypted.length})`);
        }
        const msg = decrypted.subarray(msgStart, msgEnd).toString("utf8");

        const receiveId = this.receiveId ?? "";
        if (receiveId) {
            const trailing = decrypted.subarray(msgEnd).toString("utf8");
            if (trailing !== receiveId) {
                throw new Error(`receiveId mismatch (expected "${receiveId}", got "${trailing}")`);
            }
        }

        return msg;
    }

    /**
     * 消息加密
     * 加密明文并返回 base64 格式密文与对应的新签名
     */
    public encrypt(plainText: string, timestamp: string, nonce: string): { encrypt: string; signature: string } {
        const random16 = crypto.randomBytes(16);
        const msgBuf = Buffer.from(plainText ?? "", "utf8");
        const msgLen = Buffer.alloc(4);
        msgLen.writeUInt32BE(msgBuf.length, 0);
        const receiveIdBuf = Buffer.from(this.receiveId ?? "", "utf8");

        const raw = Buffer.concat([random16, msgLen, msgBuf, receiveIdBuf]);
        const padded = pkcs7Pad(raw, CRYPTO_CONSTANTS.PKCS7_BLOCK_SIZE);
        
        const cipher = crypto.createCipheriv("aes-256-cbc", this.aesKey, this.iv);
        cipher.setAutoPadding(false);
        const encryptedBuf = Buffer.concat([cipher.update(padded), cipher.final()]);
        const encryptBase64 = encryptedBuf.toString("base64");

        const signature = this.computeSignature(timestamp, nonce, encryptBase64);

        return { encrypt: encryptBase64, signature };
    }
}
