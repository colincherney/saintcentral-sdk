/**
 * Saint Central SDK - Secure Infrastructure
 * Storage, request management, and platform detection with security validation
 * @version 3.0.0
 */

// ============================================================================
// PLATFORM DETECTOR
// ============================================================================

export class PlatformDetector {
  constructor() {
    this.info = this._detectPlatform();
  }

  _detectPlatform() {
    const isReactNative = typeof navigator !== "undefined" && navigator.product === "ReactNative";
    const isNode = typeof process !== "undefined" && process.versions && process.versions.node;
    const isBrowser = typeof window !== "undefined" && typeof window.document !== "undefined";

    return {
      isReactNative,
      isNode,
      isBrowser,
      hasAsyncStorage: isReactNative && this._checkAsyncStorage(),
      hasLocalStorage: isBrowser && this._checkLocalStorage(),
      hasCrypto: this._checkCrypto(),
      hasSecureRandom: this._checkSecureRandom(),
      encryption: this._checkEncryption(),
      authEncryptionEnabled: true,
    };
  }

  _checkAsyncStorage() {
    try {
      require("@react-native-async-storage/async-storage");
      return true;
    } catch {
      return false;
    }
  }

  _checkLocalStorage() {
    try {
      localStorage.setItem("test", "test");
      localStorage.removeItem("test");
      return true;
    } catch {
      return false;
    }
  }

  _checkCrypto() {
    if (typeof crypto !== "undefined" && crypto.subtle) return true;

    try {
      require("expo-crypto");
      return true;
    } catch {}

    try {
      require("react-native-crypto");
      return true;
    } catch {}

    return false;
  }

  _checkSecureRandom() {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) return true;

    try {
      const crypto = require("expo-crypto");
      return !!crypto.getRandomBytes;
    } catch {}

    try {
      const { randomBytes } = require("react-native-crypto");
      return !!randomBytes;
    } catch {}

    return false;
  }

  _checkEncryption() {
    if (typeof crypto !== "undefined" && crypto.subtle) {
      return {
        available: true,
        method: "web-crypto-api",
        level: "strong",
      };
    }

    try {
      require("expo-crypto");
      return {
        available: true,
        method: "expo-crypto",
        level: "strong",
      };
    } catch {}

    try {
      require("react-native-crypto");
      return {
        available: true,
        method: "react-native-crypto",
        level: "strong",
      };
    } catch {}

    return {
      available: false,
      method: "none",
      level: "none",
      warning: "Strong encryption required - install crypto dependencies",
    };
  }

  getInfo() {
    return this.info;
  }

  static checkDependencies() {
    const deps = {
      asyncStorage: false,
      crypto: false,
      base64: false,
      encryptionLevel: "none",
    };

    try {
      require("@react-native-async-storage/async-storage");
      deps.asyncStorage = true;
    } catch {}

    try {
      require("expo-crypto");
      deps.crypto = true;
      deps.encryptionLevel = "strong";
    } catch {
      try {
        require("react-native-crypto");
        deps.crypto = true;
        deps.encryptionLevel = "strong";
      } catch {
        deps.encryptionLevel = "none"; // No weak fallback
      }
    }

    try {
      require("base-64");
      deps.base64 = true;
    } catch {}

    return deps;
  }

  static getInstallInstructions() {
    const deps = PlatformDetector.checkDependencies();
    const instructions = [];

    if (!deps.asyncStorage) {
      instructions.push({
        package: "@react-native-async-storage/async-storage",
        install: "npm install @react-native-async-storage/async-storage",
        purpose: "Persistent storage for auth tokens",
        required: true,
      });
    }

    if (!deps.crypto) {
      instructions.push({
        package: "expo-crypto (recommended)",
        install: "npm install expo-crypto",
        purpose: "Strong encryption for auth operations",
        required: true, // Now required
        note: "Provides AES-256 encryption and secure random generation",
      });

      instructions.push({
        package: "react-native-crypto (alternative)",
        install: "npm install react-native-crypto",
        purpose: "AES encryption for auth operations",
        required: true, // Now required
        note: "Alternative to expo-crypto with full crypto API compatibility",
      });
    }

    if (!deps.base64) {
      instructions.push({
        package: "base-64",
        install: "npm install base-64",
        purpose: "Base64 encoding/decoding",
        required: false,
        note: "Has built-in fallback, but native implementation is faster",
      });
    }

    return {
      dependencies: deps,
      instructions,
      encryptionLevel: deps.encryptionLevel,
      summary:
        deps.encryptionLevel === "strong"
          ? "Strong encryption available. Your setup is secure."
          : "Strong encryption is required but not available. Install crypto dependencies.",
    };
  }
}

// ============================================================================
// STORAGE ADAPTER
// ============================================================================

export class StorageAdapter {
  constructor(platform, config) {
    this.platform = platform;
    this.config = config;
    this.storage = this._initializeStorage();
  }

  _initializeStorage() {
    const info = this.platform.getInfo();

    if (this.config.storage === "memory") {
      return this._createMemoryStorage();
    }

    if (info.isReactNative) {
      try {
        const AsyncStorage = require("@react-native-async-storage/async-storage").default;
        return {
          async getItem(key) {
            try {
              return await AsyncStorage.getItem(key);
            } catch {
              return null;
            }
          },
          async setItem(key, value) {
            try {
              await AsyncStorage.setItem(key, value);
            } catch {}
          },
          async removeItem(key) {
            try {
              await AsyncStorage.removeItem(key);
            } catch {}
          },
        };
      } catch {
        if (this.config.debug) {
          console.warn("Saint Central SDK: AsyncStorage not available, using memory storage");
        }
        return this._createMemoryStorage();
      }
    } else if (info.isBrowser) {
      return {
        async getItem(key) {
          try {
            return localStorage.getItem(key);
          } catch {
            return null;
          }
        },
        async setItem(key, value) {
          try {
            localStorage.setItem(key, value);
          } catch {}
        },
        async removeItem(key) {
          try {
            localStorage.removeItem(key);
          } catch {}
        },
      };
    }

    return this._createMemoryStorage();
  }

  _createMemoryStorage() {
    const store = new Map();
    return {
      async getItem(key) {
        return store.get(key) || null;
      },
      async setItem(key, value) {
        store.set(key, value);
      },
      async removeItem(key) {
        store.delete(key);
      },
    };
  }

  async getItem(key) {
    return this.storage.getItem(key);
  }

  async setItem(key, value) {
    return this.storage.setItem(key, value);
  }

  async removeItem(key) {
    return this.storage.removeItem(key);
  }

  async cleanup() {
    await this.removeItem("saint_central_auth");
    await this.removeItem("saint_central_session");
  }
}

// ============================================================================
// REQUEST MANAGER
// ============================================================================

export class RequestManager {
  constructor(config, encryption) {
    this.config = config;
    this.encryption = encryption;
    this.baseUrl = config.url;
    this.metrics = {
      requests: 0,
      failures: 0,
      totalTime: 0,
      avgTime: 0,
    };

    this.fetch = this._createFetchWithTimeout();
  }

  _createFetchWithTimeout() {
    const originalFetch = typeof fetch !== "undefined" ? fetch : require("node-fetch");

    return async (url, options = {}) => {
      const { timeout = this.config.timeout, ...fetchOptions } = options;

      if (!timeout) {
        return originalFetch(url, fetchOptions);
      }

      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("Request timeout")), timeout);
      });

      return Promise.race([originalFetch(url, fetchOptions), timeoutPromise]);
    };
  }

  async request(path, options = {}) {
    const startTime = Date.now();
    let retries = 0;
    const maxRetries = this.config.retries;

    while (retries <= maxRetries) {
      try {
        this.metrics.requests++;

        const url = `${this.baseUrl}/${path.replace(/^\//, "")}`;
        const requestOptions = await this._buildRequestOptions(options);

        const response = await this.fetch(url, requestOptions);
        const duration = Date.now() - startTime;

        this._updateMetrics(duration, true);

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(
            errorData.error?.message || errorData.message || `HTTP ${response.status}`,
          );
        }

        const result = await response.json();
        return result.data || result;
      } catch (error) {
        const duration = Date.now() - startTime;

        if (retries < maxRetries && this._shouldRetry(error)) {
          retries++;
          await this._delay(Math.pow(2, retries) * 1000);
          continue;
        }

        this._updateMetrics(duration, false);
        throw error;
      }
    }
  }

  async _buildRequestOptions(options) {
    const headers = {
      "Content-Type": "application/json",
      "X-Client-Version": "3.0.0",
      "X-Security-Level": "strong",
      ...options.headers,
    };

    if (this.encryption.sessionId) {
      headers["X-Session-ID"] = this.encryption.sessionId;
    }

    let body = options.body;
    if (
      body &&
      typeof body === "object" &&
      !options.headers?.["Content-Type"]?.includes("encrypted")
    ) {
      body = JSON.stringify(body);
    } else if (
      body &&
      typeof body === "object" &&
      options.headers?.["Content-Type"]?.includes("encrypted")
    ) {
      body = JSON.stringify(body);
    }

    return {
      method: options.method || "GET",
      headers,
      body,
      timeout: options.timeout || this.config.timeout,
    };
  }

  _shouldRetry(error) {
    return (
      error.message.includes("timeout") ||
      error.message.includes("network") ||
      error.message.includes("fetch")
    );
  }

  _delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  _updateMetrics(duration, success) {
    if (!success) this.metrics.failures++;
    this.metrics.totalTime += duration;
    this.metrics.avgTime = this.metrics.totalTime / this.metrics.requests;
  }

  getMetrics() {
    return {
      ...this.metrics,
      successRate: (this.metrics.requests - this.metrics.failures) / this.metrics.requests || 0,
    };
  }

  async cleanup() {
    this.metrics = {
      requests: 0,
      failures: 0,
      totalTime: 0,
      avgTime: 0,
    };
  }
}
