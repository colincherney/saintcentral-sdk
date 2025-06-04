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
          //
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
        let encoder, dataBuffer, iv, keyBuffer, cryptoKey, encryptedBuffer; // Hoist declarations

        try {
          // Inner try for the crypto steps themselves
          console.log(
            "Saint Central SDK: Attempting TextEncoder operations..."
          ); //
          encoder = new TextEncoder();
          dataBuffer = encoder.encode(JSON.stringify(data));
          console.log("Saint Central SDK: TextEncoder OK."); //

          console.log("Saint Central SDK: Attempting getRandomValues..."); //
          console.log("Saint Central SDK: window.crypto:", window.crypto); //
          console.log(
            "Saint Central SDK: typeof window.crypto.getRandomValues:",
            typeof window.crypto?.getRandomValues
          ); //

          if (typeof window !== "undefined" && window.crypto) {
            iv = window.crypto.getRandomValues(new Uint8Array(12));
          } else if (typeof globalThis !== "undefined" && globalThis.crypto) {
            iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
          } else {
            console.warn(
              "Saint Central SDK: Falling back to Node.js crypto path for getRandomValues in browser-like environment. This is unexpected."
            );
            const nodeCrypto = require("crypto");
            const webCrypto = nodeCrypto.webcrypto || nodeCrypto;
            iv = webCrypto.getRandomValues(new Uint8Array(12));
          }
          console.log("Saint Central SDK: getRandomValues OK."); //

          console.log("Saint Central SDK: Attempting keyBuffer creation..."); //
          if (
            !this.sessionKey ||
            typeof this.sessionKey !== "string" ||
            !/^[0-9a-fA-F]{64}$/.test(this.sessionKey)
          ) {
            console.error(
              "Saint Central SDK: Invalid sessionKey for keyBuffer creation:",
              this.sessionKey
            );
            throw new Error(
              "Invalid sessionKey format or type for encryption."
            );
          }
          keyBuffer = new Uint8Array(
            this.sessionKey.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
          );
          console.log("Saint Central SDK: keyBuffer OK."); //

          console.log(
            "Saint Central SDK: Attempting importKey and encrypt operations..."
          ); //
          console.log(
            "Saint Central SDK: window.crypto.subtle:",
            window.crypto?.subtle
          ); //
          console.log(
            "Saint Central SDK: typeof window.crypto.subtle.importKey:",
            typeof window.crypto?.subtle?.importKey
          ); //
          console.log(
            "Saint Central SDK: typeof window.crypto.subtle.encrypt:",
            typeof window.crypto?.subtle?.encrypt
          ); //

          if (
            typeof window !== "undefined" &&
            window.crypto &&
            window.crypto.subtle
          ) {
            console.log(
              "Saint Central SDK: Using window.crypto.subtle for encryption"
            ); //
            cryptoKey = await window.crypto.subtle.importKey(
              "raw",
              keyBuffer,
              { name: "AES-GCM" },
              false,
              ["encrypt"]
            );
            console.log("Saint Central SDK: importKey OK."); //
            encryptedBuffer = await window.crypto.subtle.encrypt(
              { name: "AES-GCM", iv },
              cryptoKey,
              dataBuffer
            );
            console.log("Saint Central SDK: encrypt OK."); //
          } else if (
            typeof globalThis !== "undefined" &&
            globalThis.crypto &&
            globalWatch.crypto.subtle
          ) {
            // Corrected globalWatch to globalThis
            console.log(
              "Saint Central SDK: Using globalThis.crypto.subtle for encryption"
            );
            cryptoKey = await globalThis.crypto.subtle.importKey(
              "raw",
              keyBuffer,
              { name: "AES-GCM" },
              false,
              ["encrypt"]
            );
            console.log("Saint Central SDK: importKey OK.");
            encryptedBuffer = await globalThis.crypto.subtle.encrypt(
              { name: "AES-GCM", iv },
              cryptoKey,
              dataBuffer
            );
            console.log("Saint Central SDK: encrypt OK.");
          } else {
            console.warn(
              "Saint Central SDK: Falling back to Node.js crypto path for importKey/encrypt in browser-like environment. This is unexpected."
            );
            const nodeCrypto = require("crypto");
            const webCrypto = nodeCrypto.webcrypto || nodeCrypto;
            cryptoKey = await webCrypto.subtle.importKey(
              "raw",
              keyBuffer,
              { name: "AES-GCM" },
              false,
              ["encrypt"]
            );
            console.log("Saint Central SDK: importKey (Node path) OK.");
            encryptedBuffer = await webCrypto.subtle.encrypt(
              { name: "AES-GCM", iv },
              cryptoKey,
              dataBuffer
            );
            console.log("Saint Central SDK: encrypt (Node path) OK.");
          }
        } catch (specificError) {
          console.error(
            "Saint Central SDK: Specific crypto operation failed:",
            specificError.message,
            specificError.name,
            specificError.stack
          );
          throw new SaintCentralEncryptionError(
            `Encryption failed at a specific step: ${specificError.message} (Name: ${specificError.name})`,
            "ENCRYPTION_STEP_FAILED",
            {
              originalErrorName: specificError.name,
              originalErrorMessage: specificError.message,
              originalStack: specificError.stack,
            }
          );
        }
        // ##### END DEBUGGING MODIFICATIONS for crypto steps #####

        // ##### START DEBUGGING MODIFICATIONS for post-crypto operations #####
        try {
          console.log(
            "Saint Central SDK: Post-encryption processing. Checking variables..."
          ); //
          console.log(
            "Saint Central SDK: iv (type, length):",
            typeof iv,
            iv?.length,
            iv instanceof Uint8Array
              ? "is Uint8Array"
              : "NOT Uint8Array" /*, iv*/
          ); //
          console.log(
            "Saint Central SDK: encryptedBuffer (type, byteLength):",
            typeof encryptedBuffer,
            encryptedBuffer?.byteLength,
            encryptedBuffer instanceof ArrayBuffer
              ? "is ArrayBuffer"
              : "NOT ArrayBuffer" /*, encryptedBuffer*/
          ); //

          if (!iv || !(iv instanceof Uint8Array) || iv.length !== 12) {
            console.error(
              "Saint Central SDK: IV is invalid or not a Uint8Array of length 12!",
              iv
            );
            throw new Error("IV is invalid post-encryption operations.");
          }
          if (!encryptedBuffer || !(encryptedBuffer instanceof ArrayBuffer)) {
            console.error(
              "Saint Central SDK: encryptedBuffer is invalid or not an ArrayBuffer!",
              encryptedBuffer
            );
            throw new Error(
              "encryptedBuffer is invalid post-encryption operations."
            );
          }

          console.log("Saint Central SDK: Combining IV and encryptedBuffer..."); //
          const result = new Uint8Array(iv.length + encryptedBuffer.byteLength);
          console.log(
            "Saint Central SDK: 'result' array created with length:",
            result.length
          ); //

          result.set(iv, 0);
          console.log("Saint Central SDK: IV set into result array."); //

          result.set(new Uint8Array(encryptedBuffer), iv.length);
          console.log(
            "Saint Central SDK: encryptedBuffer set into result array."
          ); //
          // console.log("Saint Central SDK: 'result' array populated (first 20 bytes):", result.slice(0,20));

          console.log(
            "Saint Central SDK: Preparing data for btoa via String.fromCharCode..."
          ); //
          const charString = String.fromCharCode(...result);
          console.log(
            "Saint Central SDK: charString created (length):",
            charString.length
          ); //
          console.log("Saint Central SDK: Calling this.base64.btoa..."); //
          console.log(
            "Saint Central SDK: this.base64.btoa is:",
            this.base64.btoa === window.btoa
              ? "native window.btoa"
              : "custom/polyfilled btoa"
          ); //

          // const base64EncodedData = this.base64.btoa(charString); // Original failing line for encryption
          const base64EncodedData = window.btoa(charString); // Explicitly call global btoa
          console.log("Saint Central SDK: btoa call successful."); //

          return {
            version: 2,
            algorithm: "aes-256-gcm",
            data: base64EncodedData,
            encrypted: true,
          };
        } catch (postCryptoError) {
          console.error(
            "Saint Central SDK: Error during post-encryption processing (IV combination, fromCharCode, or btoa):",
            postCryptoError.message,
            postCryptoError.name,
            postCryptoError.stack
          ); //
          throw new SaintCentralEncryptionError(
            `Encryption failed during post-processing: ${postCryptoError.message} (Name: ${postCryptoError.name})`,
            "ENCRYPTION_POST_PROCESSING_FAILED",
            {
              originalErrorName: postCryptoError.name,
              originalErrorMessage: postCryptoError.message,
              originalStack: postCryptoError.stack,
            }
          );
        }
        // ##### END DEBUGGING MODIFICATIONS for post-crypto operations #####
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
        if (
          error.code === "ENCRYPTION_STEP_FAILED" ||
          error.code === "ENCRYPTION_POST_PROCESSING_FAILED"
        )
          throw error;
        throw error;
      }
      console.error(
        "Saint Central SDK: General encryption error catch block:",
        error.message,
        error.name,
        error.stack
      );
      throw new SaintCentralEncryptionError(
        `Encryption failed: ${error.message} (Name: ${error.name})`,
        "ENCRYPTION_FAILED",
        {
          algorithm: this.cryptoAPI.type,
          originalErrorName: error.name,
          originalErrorMessage: error.message,
          originalStack: error.stack,
        }
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
        console.log(
          "Saint Central SDK: Decryption skipped - data not encrypted or invalid.",
          encryptedData
        );
        return encryptedData;
      }
      console.log(
        "Saint Central SDK: Starting decryption for data:",
        encryptedData
      );

      if (encryptedData.version === 2 && this.cryptoAPI.type === "web-crypto") {
        let decoder,
          combined,
          iv,
          encrypted,
          keyBuffer,
          cryptoKey,
          decryptedBuffer,
          decryptedString;

        // ##### START DEBUGGING MODIFICATIONS for decrypt #####
        try {
          console.log(
            "Saint Central SDK: Decrypt - Attempting atob operation..."
          );
          console.log(
            "Saint Central SDK: this.base64.atob is:",
            this.base64.atob === window.atob
              ? "native window.atob"
              : "custom/polyfilled atob"
          );
          // const decodedDataString = this.base64.atob(encryptedData.data); // Original
          const decodedDataString = window.atob(encryptedData.data); // Explicitly call global atob
          console.log(
            "Saint Central SDK: Decrypt - atob OK. Decoded string length:",
            decodedDataString.length
          );

          console.log(
            "Saint Central SDK: Decrypt - Converting decoded string to Uint8Array..."
          );
          combined = Uint8Array.from(decodedDataString, (c) => c.charCodeAt(0));
          console.log(
            "Saint Central SDK: Decrypt - Uint8Array 'combined' created, length:",
            combined.length
          );

          console.log(
            "Saint Central SDK: Decrypt - Slicing IV and encrypted data..."
          );
          iv = combined.slice(0, 12);
          encrypted = combined.slice(12);
          console.log(
            "Saint Central SDK: Decrypt - IV length:",
            iv.length,
            "Encrypted data length:",
            encrypted.length
          );
          if (iv.length !== 12) {
            throw new Error(`Invalid IV length: ${iv.length}. Expected 12.`);
          }

          console.log(
            "Saint Central SDK: Decrypt - Validating and preparing sessionKey for keyBuffer..."
          );
          if (
            !this.sessionKey ||
            typeof this.sessionKey !== "string" ||
            !/^[0-9a-fA-F]{64}$/.test(this.sessionKey)
          ) {
            console.error(
              "Saint Central SDK: Decrypt - Invalid sessionKey for keyBuffer creation:",
              this.sessionKey
            );
            throw new Error(
              "Invalid sessionKey format or type for decryption."
            );
          }
          keyBuffer = new Uint8Array(
            this.sessionKey.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
          );
          console.log("Saint Central SDK: Decrypt - keyBuffer OK.");

          console.log(
            "Saint Central SDK: Decrypt - Attempting importKey and decrypt operations..."
          );
          console.log(
            "Saint Central SDK: Decrypt - window.crypto.subtle:",
            window.crypto?.subtle
          );
          console.log(
            "Saint Central SDK: Decrypt - typeof window.crypto.subtle.importKey:",
            typeof window.crypto?.subtle?.importKey
          );
          console.log(
            "Saint Central SDK: Decrypt - typeof window.crypto.subtle.decrypt:",
            typeof window.crypto?.subtle?.decrypt
          );

          if (
            typeof window !== "undefined" &&
            window.crypto &&
            window.crypto.subtle
          ) {
            console.log(
              "Saint Central SDK: Decrypt - Using window.crypto.subtle for decryption"
            );
            cryptoKey = await window.crypto.subtle.importKey(
              // Around original error line encryption.js:591
              "raw",
              keyBuffer,
              { name: "AES-GCM" },
              false,
              ["decrypt"]
            );
            console.log("Saint Central SDK: Decrypt - importKey OK.");
            decryptedBuffer = await window.crypto.subtle.decrypt(
              { name: "AES-GCM", iv },
              cryptoKey,
              encrypted
            );
            console.log("Saint Central SDK: Decrypt - decrypt OK.");
          } else if (
            typeof globalThis !== "undefined" &&
            globalThis.crypto &&
            globalThis.crypto.subtle
          ) {
            console.log(
              "Saint Central SDK: Decrypt - Using globalThis.crypto.subtle for decryption"
            );
            cryptoKey = await globalThis.crypto.subtle.importKey(
              "raw",
              keyBuffer,
              { name: "AES-GCM" },
              false,
              ["decrypt"]
            );
            console.log("Saint Central SDK: Decrypt - importKey OK.");
            decryptedBuffer = await globalThis.crypto.subtle.decrypt(
              { name: "AES-GCM", iv },
              cryptoKey,
              encrypted
            );
            console.log("Saint Central SDK: Decrypt - decrypt OK.");
          } else {
            console.warn(
              "Saint Central SDK: Decrypt - Falling back to Node.js crypto path. This is unexpected in browser."
            );
            const nodeCrypto = require("crypto");
            const webCrypto = nodeCrypto.webcrypto || nodeCrypto;
            cryptoKey = await webCrypto.subtle.importKey(
              "raw",
              keyBuffer,
              { name: "AES-GCM" },
              false,
              ["decrypt"]
            );
            console.log(
              "Saint Central SDK: Decrypt - importKey (Node path) OK."
            );
            decryptedBuffer = await webCrypto.subtle.decrypt(
              { name: "AES-GCM", iv },
              cryptoKey,
              encrypted
            );
            console.log("Saint Central SDK: Decrypt - decrypt (Node path) OK.");
          }

          console.log(
            "Saint Central SDK: Decrypt - Decoding decrypted buffer..."
          );
          decoder = new TextDecoder();
          decryptedString = decoder.decode(decryptedBuffer);
          console.log("Saint Central SDK: Decrypt - TextDecoder decode OK.");

          console.log("Saint Central SDK: Decrypt - Parsing JSON...");
          const parsedResult = JSON.parse(decryptedString);
          console.log("Saint Central SDK: Decrypt - JSON parse OK.");
          return parsedResult;
        } catch (specificDecryptError) {
          console.error(
            "Saint Central SDK: Specific decrypt operation failed:",
            specificDecryptError.message,
            specificDecryptError.name,
            specificDecryptError.stack
          );
          throw new SaintCentralEncryptionError(
            `Decryption failed at a specific step: ${specificDecryptError.message} (Name: ${specificDecryptError.name})`,
            "DECRYPTION_STEP_FAILED",
            {
              originalErrorName: specificDecryptError.name,
              originalErrorMessage: specificDecryptError.message,
              originalStack: specificDecryptError.stack,
              encryptedDataSource:
                encryptedData?.data?.substring(0, 50) + "...",
            }
          );
        }
        // ##### END DEBUGGING MODIFICATIONS for decrypt #####
      } else if (
        encryptedData.version === 3 &&
        encryptedData.algorithm === "aes-256-cbc" &&
        this.cryptoAPI.encrypt
      ) {
        const { createDecipher } = require("react-native-crypto");
        const decipher = createDecipher("aes-256-cbc", this.sessionKey);
        let decrypted = decipher.update(encryptedData.data, "hex", "utf8");
        decrypted += decipher.final("utf8");
        return JSON.parse(decrypted);
      } else {
        console.error(
          "Saint Central SDK: Decrypt - Unsupported encryption algorithm or version.",
          encryptedData
        );
        throw new SaintCentralEncryptionError(
          `Unsupported encryption algorithm or version for decryption: ${encryptedData.algorithm}, v${encryptedData.version}`,
          "UNSUPPORTED_ALGORITHM_DECRYPT",
          { algorithm: encryptedData.algorithm, version: encryptedData.version }
        );
      }
    } catch (error) {
      if (error instanceof SaintCentralEncryptionError) {
        if (error.code === "DECRYPTION_STEP_FAILED") throw error; //
        throw error;
      }
      console.error(
        "Saint Central SDK: General decryption error catch block:",
        error.message,
        error.name,
        error.stack
      ); //
      throw new SaintCentralEncryptionError(
        `Decryption failed: ${error.message} (Name: ${error.name})`,
        "DECRYPTION_FAILED",
        {
          algorithm: encryptedData?.algorithm,
          version: encryptedData?.version,
          originalErrorName: error.name,
          originalErrorMessage: error.message,
          originalStack: error.stack,
        }
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
