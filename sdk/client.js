/**
 * Saint Central SDK - Secure Client Factory
 * All database operations are automatically encrypted
 * @version 3.0.0
 */

import { AuthClient } from "./auth.js";
import { DatabaseClient } from "./database.js";
import { EncryptionManager } from "./encryption.js";
import {
  StorageAdapter,
  RequestManager,
  PlatformDetector,
} from "./infrastructure.js";

export class SaintCentralClient {
  constructor(url, config = {}) {
    this.config = this._validateAndMergeConfig(url, config);
    this.platform = new PlatformDetector();

    // Check crypto availability early
    this._validateCryptoSupport();

    // Initialize core managers
    this.storage = new StorageAdapter(this.platform, this.config);
    this.encryption = new EncryptionManager(this.config, this.platform);
    this.requestManager = new RequestManager(this.config, this.encryption);

    // Initialize client modules
    this.auth = new AuthClient(this);
    this.database = new DatabaseClient(this);

    // Session management
    this._authStateListeners = new Set();

    // Initialize session for auth encryption
    this._initializeSession();
  }

  _validateAndMergeConfig(url, config) {
    if (!url || typeof url !== "string") {
      throw new Error(
        "Saint Central SDK: URL is required and must be a string"
      );
    }

    try {
      new URL(url);
    } catch {
      throw new Error("Saint Central SDK: Invalid URL provided");
    }

    return {
      url: url.replace(/\/$/, ""),
      timeout: 30000,
      retries: 2,
      enableEncryption: true,
      encryptionLevel: "strong",
      storage: "auto",
      debug: false,
      ...config,
      authEncryptionRequired: true, // Always required
      strongCryptoRequired: true, // No weak fallbacks
      alwaysEncryptDatabase: true, // NEW: Database operations always encrypted
    };
  }

  _validateCryptoSupport() {
    const platformInfo = this.platform.getInfo();

    if (!platformInfo.encryption.available) {
      const installInstructions = PlatformDetector.getInstallInstructions();

      throw new Error(
        `Strong encryption is required but not available. ` +
          `Encryption level: ${platformInfo.encryption.level}. ` +
          `Please install: ${installInstructions.instructions
            .map((i) => i.package)
            .join(", ")}`
      );
    }

    if (this.config.debug) {
      console.log("Saint Central SDK: Crypto validation passed", {
        method: platformInfo.encryption.method,
        level: platformInfo.encryption.level,
        alwaysEncryptDatabase: true,
      });
    }
  }

  async _initializeSession() {
    try {
      await this.encryption.initializeSession();
      const existingSession = await this.auth.getSession();
      if (existingSession.data?.session) {
        this._emitAuthStateChange("SIGNED_IN", existingSession.data.session);
      }
    } catch (error) {
      if (this.config.debug) {
        console.warn(
          "Saint Central SDK: Session initialization warning:",
          error.message
        );
      }
    }
  }

  // Database operations (all automatically encrypted)
  from(table) {
    return this.database.from(table);
  }

  // RPC function calls (all automatically encrypted)
  async rpc(functionName, params = {}) {
    return this.database.rpc(functionName, params);
  }

  // Utility methods
  async getUser() {
    const session = await this.auth.getSession();
    return session.data?.session?.user || null;
  }

  async isAuthenticated() {
    const session = await this.auth.getSession();
    return !!session.data?.session?.access_token;
  }

  getPlatformInfo() {
    return this.platform.getInfo();
  }

  // Auth state management
  onAuthStateChange(callback) {
    if (typeof callback !== "function") {
      throw new Error(
        "Saint Central SDK: Auth state change callback must be a function"
      );
    }

    this._authStateListeners.add(callback);

    return () => {
      this._authStateListeners.delete(callback);
    };
  }

  _emitAuthStateChange(event, session) {
    this._authStateListeners.forEach((callback) => {
      try {
        callback(event, session);
      } catch (error) {
        if (this.config.debug) {
          console.error(
            "Saint Central SDK: Auth state change callback error:",
            error
          );
        }
      }
    });
  }

  // Internal method for modules to access managers
  _getManagers() {
    return {
      storage: this.storage,
      encryption: this.encryption,
      requestManager: this.requestManager,
      platform: this.platform,
    };
  }

  // Health check
  async healthCheck() {
    try {
      const response = await this.requestManager.request("/", {
        method: "GET",
        skipAuth: true,
        timeout: 5000,
      });

      return {
        status: "healthy",
        version: response.version,
        timestamp: response.timestamp,
        platform: this.getPlatformInfo(),
        security: {
          encryptionLevel: this.platform.getInfo().encryption.level,
          strongCryptoRequired: true,
          alwaysEncryptDatabase: true, // NEW: Indicate database encryption is always on
        },
      };
    } catch (error) {
      return {
        status: "unhealthy",
        error: error.message,
        platform: this.getPlatformInfo(),
        security: {
          encryptionLevel: this.platform.getInfo().encryption.level,
          strongCryptoRequired: true,
          alwaysEncryptDatabase: true,
        },
      };
    }
  }

  // Cleanup method
  async destroy() {
    try {
      this._authStateListeners.clear();
      await this.auth.signOut();
      await this.requestManager.cleanup();
      await this.storage.cleanup();
    } catch (error) {
      if (this.config.debug) {
        console.warn("Saint Central SDK: Cleanup warning:", error.message);
      }
    }
  }
}

// Main factory function
export function createClient(url, config = {}) {
  return new SaintCentralClient(url, config);
}

// Error classes
export class SaintCentralError extends Error {
  constructor(message, code, details) {
    super(message);
    this.name = "SaintCentralError";
    this.code = code;
    this.details = details;
  }
}

export class SaintCentralAuthError extends SaintCentralError {
  constructor(message, code, details) {
    super(message, code, details);
    this.name = "SaintCentralAuthError";
  }
}

export class SaintCentralDatabaseError extends SaintCentralError {
  constructor(message, code, details) {
    super(message, code, details);
    this.name = "SaintCentralDatabaseError";
  }
}

export class SaintCentralStorageError extends SaintCentralError {
  constructor(message, code, details) {
    super(message, code, details);
    this.name = "SaintCentralStorageError";
  }
}

export class SaintCentralEncryptionError extends SaintCentralError {
  constructor(message, code, details) {
    super(message, code, details);
    this.name = "SaintCentralEncryptionError";
  }
}

export const version = "3.0.0";
export default createClient;
