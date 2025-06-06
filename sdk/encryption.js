/**
 * Saint Central SDK - AES-256-GCM Encryption Module
 * React Native AES Crypto - No fallbacks
 * @version 3.0.0
 */

import Aes from "react-native-aes-crypto";
import * as Crypto from "expo-crypto";

export class EncryptionManager {
  constructor(config, platform) {
    this.config = config;
    this.platform = platform;
    this.sessionKey = null;
    this.sessionId = null;
    this.sessionExpiry = null;
  }

  async initializeSession() {
    try {
      this.sessionKey = await this.generateKey();
      this.sessionId = await this.generateSessionId();
      this.sessionExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    } catch (error) {
      throw new Error(`Encryption initialization failed: ${error.message}`);
    }
  }

  async ensureSession() {
    if (!this.sessionKey || !this.sessionId || Date.now() > this.sessionExpiry) {
      await this.initializeSession();
    }
  }

  async encrypt(data) {
    await this.ensureSession();

    try {
      const dataString = typeof data === "string" ? data : JSON.stringify(data);

      // Generate IV (12 bytes for GCM)
      const ivBytes = await Crypto.getRandomBytesAsync(12);
      const iv = this.arrayToBase64(ivBytes);

      // Encrypt using AES-256-GCM
      const encrypted = await Aes.encrypt(dataString, this.sessionKey, iv, "aes-256-gcm");

      return {
        version: 3,
        algorithm: "aes-256-gcm",
        data: encrypted,
        iv: iv,
        encrypted: true,
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  async decrypt(encryptedData) {
    if (!encryptedData || !encryptedData.encrypted) {
      return encryptedData;
    }

    await this.ensureSession();

    try {
      // Decrypt using AES-256-GCM
      const decrypted = await Aes.decrypt(
        encryptedData.data,
        this.sessionKey,
        encryptedData.iv,
        "aes-256-gcm",
      );

      try {
        return JSON.parse(decrypted);
      } catch {
        return decrypted;
      }
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  async generateKey() {
    // Generate 256-bit key
    const key = await Aes.randomKey(32);
    return key;
  }

  async generateSessionId() {
    const bytes = await Crypto.getRandomBytesAsync(16);
    return this.arrayToHex(bytes);
  }

  isEncrypted(data) {
    return data && data.encrypted === true && data.version === 3;
  }

  getEncryptionInfo() {
    return {
      type: "react-native-aes-crypto",
      hasSession: !!this.sessionKey,
      sessionExpiry: this.sessionExpiry,
      enabled: true,
      supportsEncryption: true,
      strongCryptoRequired: true,
      alwaysEncryptDatabase: true,
    };
  }

  async cleanup() {
    this.sessionKey = null;
    this.sessionId = null;
    this.sessionExpiry = null;
  }

  // Helper methods
  arrayToBase64(array) {
    const bytes = new Uint8Array(array);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  arrayToHex(array) {
    return Array.from(new Uint8Array(array))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
}

// For compatibility with the existing encryption.js export pattern
export class SecureEncryption {
  constructor() {
    this.initialized = false;
    this.sessionKey = null;
  }

  async initCrypto() {
    if (this.initialized) return;

    try {
      // Test that react-native-aes-crypto is available
      await Aes.randomKey(32);
      this.initialized = true;
    } catch (error) {
      throw new Error("react-native-aes-crypto not available. Please install it.");
    }
  }

  async encrypt(data, key) {
    await this.initCrypto();

    const dataString = typeof data === "string" ? data : JSON.stringify(data);
    const keyToUse = key || (await this.generateKey());

    // Generate IV
    const ivBytes = await Crypto.getRandomBytesAsync(12);
    const iv = this.arrayToBase64(ivBytes);

    const encrypted = await Aes.encrypt(dataString, keyToUse, iv, "aes-256-gcm");

    return {
      version: 3,
      algorithm: "aes-256-gcm",
      data: encrypted,
      iv: iv,
      encrypted: true,
    };
  }

  async decrypt(encryptedData, key) {
    if (!encryptedData?.encrypted) return encryptedData;

    await this.initCrypto();

    const decrypted = await Aes.decrypt(encryptedData.data, key, encryptedData.iv, "aes-256-gcm");

    try {
      return JSON.parse(decrypted);
    } catch {
      return decrypted;
    }
  }

  async generateKey() {
    await this.initCrypto();
    const keyBytes = await Crypto.getRandomBytesAsync(32);
    return keyBytes;
  }

  async generateKeyBase64() {
    const key = await this.generateKey();
    return this.arrayToBase64(key);
  }

  keyFromBase64(base64Key) {
    const binary = atob(base64Key);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  isEncrypted(data) {
    return data?.encrypted === true;
  }

  async getPlatformInfo() {
    try {
      await this.initCrypto();
      return { type: "react-native-aes-crypto", secure: true };
    } catch {
      return { type: "unavailable", secure: false };
    }
  }

  async test() {
    try {
      const key = await this.generateKey();
      const testData = { test: "data" };
      const encrypted = await this.encrypt(testData, key);
      const decrypted = await this.decrypt(encrypted, key);

      return {
        success: JSON.stringify(testData) === JSON.stringify(decrypted),
        platform: "react-native-aes-crypto",
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  // Helper methods
  arrayToBase64(array) {
    const bytes = new Uint8Array(array);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  base64ToArray(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

export const encryption = new SecureEncryption();
export default SecureEncryption;
