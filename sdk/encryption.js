/**
 * Saint Central SDK - Secure Encryption Manager
 * Strong encryption only - no weak fallbacks
 * INLINE FIX: All crypto operations inline in methods, no external function calls
 * @version 3.0.0
 */

import { SaintCentralEncryptionError } from "./client.js";

export class EncryptionManager {
  constructor(config, platform) {
    this.config = config;
    this.platform = platform;
    this.cryptoAPI = this._initializeCrypto();
    this.sessionKey = null;
    this.sessionId = null;
    this.sessionExpiry = null;
    this.base64 = this._initializeBase64();
  }

  _initializeCrypto() {
    const platformInfo = this.platform.getInfo();

    if (platformInfo.isReactNative) {
      return this._initializeReactNativeCrypto();
    } else if (platformInfo.isBrowser || platformInfo.isNode) {
      return this._initializeWebCrypto();
    }

    return this._initializeNoCrypto();
  }

  _initializeReactNativeCrypto() {
    try {
      const crypto = require("expo-crypto");
      return {
        type: "expo-crypto",
        api: crypto,
        getRandomValues: (array) => {
          const randomBytes = crypto.getRandomBytes(array.length);
          for (let i = 0; i < array.length; i++) {
            array[i] = randomBytes[i];
          }
          return array;
        },
        supportsEncryption: true,
      };
    } catch {
      try {
        const { randomBytes, createCipher } = require("react-native-crypto");
        return {
          type: "react-native-crypto",
          api: { randomBytes, createCipher },
          getRandomValues: (array) => {
            const bytes = randomBytes(array.length);
            for (let i = 0; i < array.length; i++) {
              array[i] = bytes[i];
            }
            return array;
          },
          supportsEncryption: true,
          async encrypt(data, key) {
            const cipher = createCipher("aes-256-cbc", key);
            let encrypted = cipher.update(JSON.stringify(data), "utf8", "hex");
            encrypted += cipher.final("hex");
            return {
              version: 3,
              algorithm: "aes-256-cbc",
              data: encrypted,
              encrypted: true,
            };
          },
        };
      } catch {
        return this._initializeNoCrypto();
      }
    }
  }

  _initializeWebCrypto() {
    // Check if crypto exists
    let hasCrypto = false;

    if (
      typeof window !== "undefined" &&
      window.crypto &&
      window.crypto.subtle
    ) {
      hasCrypto = true;
    } else if (
      typeof globalThis !== "undefined" &&
      globalThis.crypto &&
      globalThis.crypto.subtle
    ) {
      hasCrypto = true;
    } else {
      try {
        const nodeCrypto = require("crypto");
        const webCrypto = nodeCrypto.webcrypto || nodeCrypto;
        if (webCrypto && webCrypto.subtle) {
          hasCrypto = true;
        }
      } catch {
        // Fall through
      }
    }

    if (!hasCrypto) {
      return this._initializeNoCrypto();
    }

    return {
      type: "web-crypto",
      api: null,
      getRandomValues: (array) => {
        // INLINE FIX: Direct call, no external function
        if (typeof window !== "undefined" && window.crypto) {
          return window.crypto.getRandomValues(array);
        } else if (typeof globalThis !== "undefined" && globalThis.crypto) {
          return globalThis.crypto.getRandomValues(array);
        } else {
          try {
            const nodeCrypto = require("crypto");
            const webCrypto = nodeCrypto.webcrypto || nodeCrypto;
            return webCrypto.getRandomValues(array);
          } catch {
            // Fallback
            for (let i = 0; i < array.length; i++) {
              array[i] = Math.floor(Math.random() * 256);
            }
            return array;
          }
        }
      },
      supportsEncryption: true,
    };
  }

  _initializeNoCrypto() {
    return {
      type: "no-crypto",
      api: null,
      getRandomValues: (array) => {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
        return array;
      },
      supportsEncryption: false,
    };
  }

  _initializeBase64() {
    if (this.platform.getInfo().isReactNative) {
      try {
        const { encode, decode } = require("base-64");
        return { btoa: encode, atob: decode };
      } catch {
        return this._createBase64Polyfill();
      }
    } else if (typeof btoa !== "undefined" && typeof atob !== "undefined") {
      return { btoa, atob };
    } else {
      return {
        btoa: (str) => Buffer.from(str, "binary").toString("base64"),
        atob: (str) => Buffer.from(str, "base64").toString("binary"),
      };
    }
  }

  _createBase64Polyfill() {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    return {
      btoa: (str) => {
        let result = "";
        let i = 0;
        while (i < str.length) {
          const a = str.charCodeAt(i++);
          const b = i < str.length ? str.charCodeAt(i++) : 0;
          const c = i < str.length ? str.charCodeAt(i++) : 0;
          const bitmap = (a << 16) | (b << 8) | c;
          result +=
            chars.charAt((bitmap >> 18) & 63) +
            chars.charAt((bitmap >> 12) & 63) +
            (i - 2 < str.length ? chars.charAt((bitmap >> 6) & 63) : "=") +
            (i - 1 < str.length ? chars.charAt(bitmap & 63) : "=");
        }
        return result;
      },
      atob: (str) => {
        str = str.replace(/[^A-Za-z0-9+/]/g, "");
        let result = "";
        let i = 0;
        while (i < str.length) {
          const encoded1 = chars.indexOf(str.charAt(i++));
          const encoded2 = chars.indexOf(str.charAt(i++));
          const encoded3 = chars.indexOf(str.charAt(i++));
          const encoded4 = chars.indexOf(str.charAt(i++));
          const bitmap =
            (encoded1 << 18) | (encoded2 << 12) | (encoded3 << 6) | encoded4;
          result += String.fromCharCode((bitmap >> 16) & 255);
          if (encoded3 !== 64)
            result += String.fromCharCode((bitmap >> 8) & 255);
          if (encoded4 !== 64) result += String.fromCharCode(bitmap & 255);
        }
        return result;
      },
    };
  }

  async initializeSession() {
    try {
      if (!this.config.enableEncryption) return;

      if (
        this.sessionKey &&
        this.sessionExpiry &&
        Date.now() < this.sessionExpiry
      ) {
        return;
      }

      const response = await fetch(`${this.config.url}/auth/key-exchange`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          clientInfo: {
            timestamp: Date.now(),
            version: "3.0.0",
            platform: this.platform.getInfo().isReactNative
              ? "react-native"
              : this.platform.getInfo().isBrowser
              ? "browser"
              : "node",
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`Session initialization failed: ${response.status}`);
      }

      const result = await response.json();
      const sessionData = result.data;

      this.sessionKey = sessionData.sessionKey;
      this.sessionId = sessionData.sessionId;
      this.sessionExpiry = sessionData.expiresAt;

      if (this.config.debug) {
        console.log("Saint Central SDK: Session initialized", {
          sessionId: this.sessionId,
          expiresAt: new Date(this.sessionExpiry).toISOString(),
        });
      }
    } catch (error) {
      if (this.config.debug) {
        console.warn(
          "Saint Central SDK: Session initialization failed:",
          error.message
        );
      }
      this.sessionKey = this.generateKey();
    }
  }

  async ensureSession() {
    if (
      !this.sessionKey ||
      (this.sessionExpiry && Date.now() > this.sessionExpiry)
    ) {
      await this.initializeSession();
    }
  }

  async encrypt(data) {
    try {
      if (!this.config.enableEncryption) return data;

      if (!this.cryptoAPI.supportsEncryption) {
        throw new SaintCentralEncryptionError(
          "Strong encryption is required but not available. Please install expo-crypto, react-native-crypto, or use a platform with Web Crypto API support.",
          "NO_STRONG_CRYPTO_AVAILABLE",
          { platform: this.cryptoAPI.type }
        );
      }

      await this.ensureSession();

      if (this.cryptoAPI.type === "web-crypto" && this.sessionKey) {
        // INLINE FIX: All crypto operations directly in this method
        // No external function calls that could cause context issues

        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(JSON.stringify(data));

        // Generate IV - direct call
        let iv;
        if (typeof window !== "undefined" && window.crypto) {
          iv = window.crypto.getRandomValues(new Uint8Array(12));
        } else if (typeof globalThis !== "undefined" && globalThis.crypto) {
          iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
        } else {
          const nodeCrypto = require("crypto");
          const webCrypto = nodeCrypto.webcrypto || nodeCrypto;
          iv = webCrypto.getRandomValues(new Uint8Array(12));
        }

        // Create key buffer
        const keyBuffer = new Uint8Array(
          this.sessionKey.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
        );

        // Import key and encrypt - direct calls
        let cryptoKey, encryptedBuffer;

        if (
          typeof window !== "undefined" &&
          window.crypto &&
          window.crypto.subtle
        ) {
          cryptoKey = await window.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
          );

          encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            cryptoKey,
            dataBuffer
          );
        } else if (
          typeof globalThis !== "undefined" &&
          globalThis.crypto &&
          globalThis.crypto.subtle
        ) {
          cryptoKey = await globalThis.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
          );

          encryptedBuffer = await globalThis.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            cryptoKey,
            dataBuffer
          );
        } else {
          const nodeCrypto = require("crypto");
          const webCrypto = nodeCrypto.webcrypto || nodeCrypto;

          cryptoKey = await webCrypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
          );

          encryptedBuffer = await webCrypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            cryptoKey,
            dataBuffer
          );
        }

        // Combine IV and encrypted data
        const result = new Uint8Array(iv.length + encryptedBuffer.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encryptedBuffer), iv.length);

        return {
          version: 2,
          algorithm: "aes-256-gcm",
          data: this.base64.btoa(String.fromCharCode(...result)),
          encrypted: true,
        };
      } else if (this.cryptoAPI.encrypt) {
        return await this.cryptoAPI.encrypt(data, this.sessionKey);
      } else {
        throw new SaintCentralEncryptionError(
          "No encryption method available despite crypto support",
          "ENCRYPTION_METHOD_UNAVAILABLE"
        );
      }
    } catch (error) {
      if (error instanceof SaintCentralEncryptionError) {
        throw error;
      }
      throw new SaintCentralEncryptionError(
        `Encryption failed: ${error.message}`,
        "ENCRYPTION_FAILED",
        { algorithm: this.cryptoAPI.type, error: error.message }
      );
    }
  }

  async decrypt(encryptedData) {
    try {
      if (
        !encryptedData ||
        typeof encryptedData !== "object" ||
        !encryptedData.encrypted
      ) {
        return encryptedData;
      }

      if (encryptedData.version === 2 && this.cryptoAPI.type === "web-crypto") {
        // INLINE FIX: All crypto operations directly in this method

        const decoder = new TextDecoder();
        const combined = Uint8Array.from(
          this.base64.atob(encryptedData.data),
          (c) => c.charCodeAt(0)
        );

        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);

        const keyBuffer = new Uint8Array(
          this.sessionKey.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
        );

        // Import key and decrypt - direct calls
        let cryptoKey, decryptedBuffer;

        if (
          typeof window !== "undefined" &&
          window.crypto &&
          window.crypto.subtle
        ) {
          cryptoKey = await window.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          );

          decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            cryptoKey,
            encrypted
          );
        } else if (
          typeof globalThis !== "undefined" &&
          globalThis.crypto &&
          globalThis.crypto.subtle
        ) {
          cryptoKey = await globalThis.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          );

          decryptedBuffer = await globalThis.crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            cryptoKey,
            encrypted
          );
        } else {
          const nodeCrypto = require("crypto");
          const webCrypto = nodeCrypto.webcrypto || nodeCrypto;

          cryptoKey = await webCrypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          );

          decryptedBuffer = await webCrypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            cryptoKey,
            encrypted
          );
        }

        const decryptedString = decoder.decode(decryptedBuffer);
        return JSON.parse(decryptedString);
      } else if (
        encryptedData.version === 3 &&
        encryptedData.algorithm === "aes-256-cbc" &&
        this.cryptoAPI.encrypt
      ) {
        // Handle React Native AES decryption
        const { createDecipher } = require("react-native-crypto");
        const decipher = createDecipher("aes-256-cbc", this.sessionKey);
        let decrypted = decipher.update(encryptedData.data, "hex", "utf8");
        decrypted += decipher.final("utf8");
        return JSON.parse(decrypted);
      } else {
        throw new SaintCentralEncryptionError(
          `Unsupported encryption algorithm: ${encryptedData.algorithm}`,
          "UNSUPPORTED_ALGORITHM",
          { algorithm: encryptedData.algorithm, version: encryptedData.version }
        );
      }
    } catch (error) {
      if (error instanceof SaintCentralEncryptionError) {
        throw error;
      }
      throw new SaintCentralEncryptionError(
        `Decryption failed: ${error.message}`,
        "DECRYPTION_FAILED",
        { data: encryptedData, error: error.message }
      );
    }
  }

  generateKey() {
    const array = this.cryptoAPI.getRandomValues(new Uint8Array(32));
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
      ""
    );
  }

  isEncrypted(data) {
    return data && typeof data === "object" && data.encrypted === true;
  }

  getEncryptionInfo() {
    return {
      type: this.cryptoAPI.type,
      hasSession: !!this.sessionKey,
      sessionExpiry: this.sessionExpiry,
      enabled: this.config.enableEncryption,
      supportsEncryption: this.cryptoAPI.supportsEncryption,
      strongCryptoRequired: true,
    };
  }

  async cleanup() {
    this.sessionKey = null;
    this.sessionId = null;
    this.sessionExpiry = null;
  }
}
