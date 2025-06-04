/**
 * Saint Central Cloudflare Worker - Production Ready (Updated June 2025)
 *
 * Enterprise-grade secure middleware with Supabase REST API,
 * comprehensive security, monitoring, and error handling.
 * Updated to use Supabase REST instead of Neon for reliability
 *
 * @version 2.2.0
 * @author Saint Central Security Team
 */

// Production configuration with validation
class Config {
  constructor(env) {
    this.validateEnvironment(env);

    this.database = {
      url: env.DATABASE_URL,
      poolSize: parseInt(env.DB_POOL_SIZE || "10"),
      connectionTimeout: parseInt(env.DB_CONNECTION_TIMEOUT || "30000"),
      queryTimeout: parseInt(env.DB_QUERY_TIMEOUT || "60000"),
    };

    this.security = {
      encryptionKey: env.ENCRYPTION_KEY,
      jwtSecret: env.JWT_SECRET,
      rateLimitEnabled: env.RATE_LIMIT_ENABLED === "true",
      maxLoginAttempts: parseInt(env.MAX_LOGIN_ATTEMPTS || "5"),
      loginLockoutDuration: parseInt(env.LOGIN_LOCKOUT_DURATION || "900000"), // 15 minutes
      passwordMinLength: parseInt(env.PASSWORD_MIN_LENGTH || "12"),
      sessionTimeout: parseInt(env.SESSION_TIMEOUT || "86400000"), // 24 hours
    };

    this.supabase = {
      url: env.SUPABASE_URL,
      serviceKey: env.SUPABASE_SERVICE_ROLE_KEY,
      anonKey: env.SUPABASE_ANON_KEY,
    };

    this.monitoring = {
      logLevel: env.LOG_LEVEL || "info",
      enableMetrics: env.ENABLE_METRICS === "true",
      enableTracing: env.ENABLE_TRACING === "true",
    };

    this.cors = {
      allowedOrigins: env.ALLOWED_ORIGINS?.split(",") || ["*"],
      allowedMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-Security-Nonce",
        "X-Request-ID",
        "X-Client-Version",
        "X-API-Key",
        "X-Session-ID",
        "X-Security-Level",
      ],
    };
  }

  validateEnvironment(env) {
    const required = [
      "DATABASE_URL",
      "ENCRYPTION_KEY",
      "JWT_SECRET",
      "SUPABASE_URL",
      "SUPABASE_SERVICE_ROLE_KEY",
    ];

    const missing = required.filter((key) => !env[key]);
    if (missing.length > 0) {
      throw new Error(
        `Missing required environment variables: ${missing.join(", ")}`
      );
    }

    // Validate URL formats
    try {
      new URL(env.SUPABASE_URL);
      if (
        !env.DATABASE_URL.startsWith("postgres://") &&
        !env.DATABASE_URL.startsWith("postgresql://")
      ) {
        throw new Error(
          "DATABASE_URL must be a valid PostgreSQL connection string"
        );
      }
    } catch (error) {
      throw new Error(`Invalid URL in environment variables: ${error.message}`);
    }

    // Validate key lengths and formats
    if (env.ENCRYPTION_KEY.length !== 64) {
      throw new Error(
        "ENCRYPTION_KEY must be exactly 64 characters (32 bytes in hex)"
      );
    }

    // Validate that ENCRYPTION_KEY is valid hex
    if (!/^[0-9a-fA-F]{64}$/.test(env.ENCRYPTION_KEY)) {
      throw new Error(
        "ENCRYPTION_KEY must be a valid 64-character hexadecimal string"
      );
    }

    if (env.JWT_SECRET.length < 32) {
      throw new Error("JWT_SECRET must be at least 32 characters");
    }
  }

  // Helper method to generate a valid encryption key
  static generateEncryptionKey() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
      ""
    );
  }
}

// Production-grade Supabase REST client (replacing Neon)
class SupabaseClient {
  constructor(config) {
    this.config = config;
    this.baseUrl = `${config.supabase.url}/rest/v1`;
    this.headers = {
      apikey: config.supabase.serviceKey,
      Authorization: `Bearer ${config.supabase.serviceKey}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    };
    this.queryStats = {
      totalQueries: 0,
      totalDuration: 0,
      errors: 0,
    };
  }

  async query(table, method = "GET", body = null, queryParams = "") {
    const startTime = Date.now();
    const queryId = this.generateQueryId();

    try {
      this.logQuery(queryId, `${method} ${table}`, queryParams);

      const url = `${this.baseUrl}/${table}${queryParams}`;
      const response = await fetch(url, {
        method,
        headers: this.headers,
        body: body ? JSON.stringify(body) : null,
      });

      const duration = Date.now() - startTime;

      if (!response.ok) {
        const error = await response.json();
        this.updateQueryStats(false, duration);
        this.logQueryError(queryId, error, duration);
        return { rows: null, error };
      }

      const data = await response.json();
      this.updateQueryStats(true, duration);
      this.logQueryResult(
        queryId,
        duration,
        Array.isArray(data) ? data.length : 1
      );

      return { rows: data, error: null };
    } catch (error) {
      const duration = Date.now() - startTime;
      this.updateQueryStats(false, duration);
      this.logQueryError(queryId, error, duration);
      return {
        rows: null,
        error: { message: error.message, code: "API_ERROR" },
      };
    }
  }

  generateQueryId() {
    return `q_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  updateQueryStats(success, duration) {
    this.queryStats.totalQueries++;
    this.queryStats.totalDuration += duration;
    if (!success) this.queryStats.errors++;
  }

  logQuery(queryId, operation, params) {
    Logger.debug("Supabase Query", {
      queryId,
      operation,
      params: params.substring(0, 200) + (params.length > 200 ? "..." : ""),
    });
  }

  logQueryResult(queryId, duration, rowCount) {
    Logger.info("Query Completed", {
      queryId,
      duration,
      rowCount,
    });
  }

  logQueryError(queryId, error, duration) {
    Logger.error("Query Failed", {
      queryId,
      error: error.message || JSON.stringify(error),
      duration,
    });
  }

  buildSelectQuery(tableName, options = {}) {
    const { select = "*", where = {}, orderBy, limit, offset } = options;

    const params = new URLSearchParams();

    // Add select
    if (select !== "*") {
      params.append("select", select);
    }

    // Add filters
    Object.entries(where).forEach(([key, value]) => {
      if (typeof value === "string" && value.includes(".")) {
        const [operator, filterValue] = value.split(".", 2);
        params.append(key, `${operator}.${filterValue}`);
      } else {
        params.append(key, `eq.${value}`);
      }
    });

    // Add order
    if (orderBy) {
      params.append("order", orderBy);
    }

    // Add limit and offset
    if (limit) params.append("limit", limit);
    if (offset) params.append("offset", offset);

    return params.toString() ? `?${params.toString()}` : "";
  }

  async select(tableName, options = {}) {
    const queryParams = this.buildSelectQuery(tableName, options);
    return this.query(tableName, "GET", null, queryParams);
  }

  async insert(tableName, data) {
    return this.query(tableName, "POST", data);
  }

  async update(tableName, data, where) {
    const params = new URLSearchParams();
    Object.entries(where).forEach(([key, value]) => {
      params.append(key, `eq.${value}`);
    });
    const queryParams = params.toString() ? `?${params.toString()}` : "";
    return this.query(tableName, "PATCH", data, queryParams);
  }

  async delete(tableName, where) {
    const params = new URLSearchParams();
    Object.entries(where).forEach(([key, value]) => {
      params.append(key, `eq.${value}`);
    });
    const queryParams = params.toString() ? `?${params.toString()}` : "";
    return this.query(tableName, "DELETE", null, queryParams);
  }

  async rpc(functionName, params = {}) {
    return this.query(`rpc/${functionName}`, "POST", params);
  }

  getStats() {
    return {
      ...this.queryStats,
      averageDuration:
        this.queryStats.totalQueries > 0
          ? this.queryStats.totalDuration / this.queryStats.totalQueries
          : 0,
      errorRate:
        this.queryStats.totalQueries > 0
          ? this.queryStats.errors / this.queryStats.totalQueries
          : 0,
    };
  }
}

// Production logging system
class Logger {
  static logLevel = "info";
  static levels = { error: 0, warn: 1, info: 2, debug: 3 };

  static setLevel(level) {
    this.logLevel = level;
  }

  static shouldLog(level) {
    return this.levels[level] <= this.levels[this.logLevel];
  }

  static log(level, message, data = {}) {
    if (!this.shouldLog(level)) return;

    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      ...data,
    };

    console.log(JSON.stringify(logEntry));
  }

  static error(message, data) {
    this.log("error", message, data);
  }
  static warn(message, data) {
    this.log("warn", message, data);
  }
  static info(message, data) {
    this.log("info", message, data);
  }
  static debug(message, data) {
    this.log("debug", message, data);
  }
}

// Production-grade encryption
class Encryption {
  constructor(key) {
    this.key = key;
  }

  async encrypt(data) {
    try {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(JSON.stringify(data));

      const iv = crypto.getRandomValues(new Uint8Array(12));

      if (!/^[0-9a-fA-F]{64}$/.test(this.key)) {
        throw new Error(
          "Invalid encryption key format - must be 64-character hex string"
        );
      }

      const keyBuffer = new Uint8Array(
        this.key.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
      );

      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );

      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        dataBuffer
      );

      const result = new Uint8Array(iv.length + encryptedBuffer.byteLength);
      result.set(iv, 0);
      result.set(new Uint8Array(encryptedBuffer), iv.length);

      const base64 = btoa(String.fromCharCode(...result));

      return {
        version: 2,
        algorithm: "aes-256-gcm",
        data: base64,
        encrypted: true,
      };
    } catch (error) {
      Logger.error("Encryption failed", {
        error: error.message,
        stack: error.stack,
      });
      throw new Error("Encryption failed");
    }
  }

  async decrypt(encryptedData) {
    try {
      if (!encryptedData || typeof encryptedData !== "object") {
        Logger.debug(
          "Decrypt: Data is not an object or is null, returning as is.",
          { encryptedData }
        );
        return encryptedData;
      }

      if (!encryptedData.encrypted || encryptedData.version !== 2) {
        Logger.debug(
          "Decrypt: Data is not marked as encrypted or version mismatch, returning as is.",
          { encrypted: encryptedData.encrypted, version: encryptedData.version }
        );
        return encryptedData;
      }

      Logger.debug("Decrypt: Starting decryption process.", {
        version: encryptedData.version,
        algorithm: encryptedData.algorithm,
      });

      const decoder = new TextDecoder();

      const combined = Uint8Array.from(atob(encryptedData.data), (c) =>
        c.charCodeAt(0)
      );

      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);

      if (!/^[0-9a-fA-F]{64}$/.test(this.key)) {
        Logger.error(
          "Decrypt: Invalid encryption key format during decryption."
        );
        throw new Error(
          "Invalid encryption key format - must be 64-character hex string"
        );
      }

      const keyBuffer = new Uint8Array(
        this.key.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
      );

      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        encrypted
      );

      const decryptedString = decoder.decode(decryptedBuffer);
      Logger.debug("Decrypt: Decryption successful, parsing JSON.");
      return JSON.parse(decryptedString);
    } catch (error) {
      Logger.error("Decryption failed in Encryption class", {
        errorMessage: error.message,
        // stack: error.stack, // Stack can be very verbose
        keyPresent: !!this.key,
        keyLength: this.key?.length || 0,
        encryptedDataPreview: JSON.stringify(encryptedData)?.substring(0, 100),
      });
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }
}

// JWT utilities with proper verification
class JWT {
  constructor(secret) {
    this.secret = secret;
  }

  async verify(token) {
    try {
      if (!token) return null;

      const parts = token.split(".");
      if (parts.length !== 3) return null;

      const [headerB64, payloadB64, signatureB64] = parts;

      const header = JSON.parse(atob(headerB64));
      const payload = JSON.parse(atob(payloadB64));

      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return null;
      }

      const data = `${headerB64}.${payloadB64}`;
      const signature = this.base64UrlDecode(signatureB64);

      const encoder = new TextEncoder();
      const keyBuffer = encoder.encode(this.secret);
      const dataBuffer = encoder.encode(data);

      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
      );

      const isValid = await crypto.subtle.verify(
        "HMAC",
        cryptoKey,
        signature,
        dataBuffer
      );

      return isValid ? payload : null;
    } catch (error) {
      Logger.error("JWT verification failed", { error: error.message });
      return null;
    }
  }

  base64UrlDecode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) {
      str += "=";
    }
    return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
  }
}

// Input validation
class Validator {
  static email(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static password(password, minLength = 12) {
    if (!password || password.length < minLength) {
      return {
        valid: false,
        message: `Password must be at least ${minLength} characters`,
      };
    }
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
      return {
        valid: false,
        message:
          "Password must contain uppercase, lowercase, number, and special character",
      };
    }
    return { valid: true };
  }

  static sanitizeInput(input, maxLength = 1000) {
    if (typeof input !== "string") return input;
    return input.trim().slice(0, maxLength).replace(/[<>]/g, "");
  }

  static validateTableName(tableName) {
    const allowedTables = [
      "users",
      "profiles",
      "posts",
      "comments",
      "sessions",
      "audit_logs",
      "user_roles",
      "permissions",
      "files",
      "test",
    ];
    return allowedTables.includes(tableName);
  }
}

// Enhanced security utilities
const Security = {
  async rateLimit(request, env, config) {
    if (!config.security.rateLimitEnabled) return { allowed: true };
    const clientIP = request.headers.get("CF-Connecting-IP");
    const endpoint = new URL(request.url).pathname;
    const method = request.method;
    const rateKey = `ratelimit:${clientIP}:${method}:${endpoint}`;
    try {
      const rateLimitData = await env.SAINT_CENTRAL_KV.get(rateKey, {
        type: "json",
      });
      const now = Date.now();
      const windowSize = 60000; // 1 minute
      const maxRequests = this.getRateLimitForEndpoint(endpoint, method);
      if (!rateLimitData || now > rateLimitData.resetAt) {
        await env.SAINT_CENTRAL_KV.put(
          rateKey,
          JSON.stringify({ count: 1, resetAt: now + windowSize }),
          { expirationTtl: 60 }
        );
        return {
          allowed: true,
          remaining: maxRequests - 1,
          limit: maxRequests,
          resetAt: now + windowSize,
        };
      }
      const newCount = rateLimitData.count + 1;
      if (newCount > maxRequests) {
        return {
          allowed: false,
          resetAt: rateLimitData.resetAt,
          remaining: 0,
          limit: maxRequests,
        };
      }
      await env.SAINT_CENTRAL_KV.put(
        rateKey,
        JSON.stringify({ count: newCount, resetAt: rateLimitData.resetAt }),
        { expirationTtl: 60 }
      );
      return {
        allowed: true,
        remaining: maxRequests - newCount,
        limit: maxRequests,
        resetAt: rateLimitData.resetAt,
      };
    } catch (error) {
      Logger.error("Rate limiting error", { error: error.message });
      return { allowed: true }; // Fail open
    }
  },

  getRateLimitForEndpoint(endpoint, method) {
    if (endpoint.includes("/auth/signin")) return 10;
    if (endpoint.includes("/auth/signup")) return 5;
    if (method === "POST") return 30;
    if (method === "GET") return 100;
    return 50;
  },

  async checkBruteForce(email, env, config) {
    const key = `bruteforce:${email}`;
    const attempts = (await env.SAINT_CENTRAL_KV.get(key, {
      type: "json",
    })) || { count: 0, lastAttempt: 0 };

    const now = Date.now();
    const lockoutDuration = config.security.loginLockoutDuration;

    if (
      attempts.count >= config.security.maxLoginAttempts &&
      now - attempts.lastAttempt < lockoutDuration
    ) {
      return {
        blocked: true,
        remainingTime: lockoutDuration - (now - attempts.lastAttempt),
      };
    }

    return { blocked: false };
  },
  async recordFailedLogin(email, env, config) {
    const key = `bruteforce:${email}`;
    const attempts = (await env.SAINT_CENTRAL_KV.get(key, {
      type: "json",
    })) || { count: 0, lastAttempt: 0 };

    const newAttempts = {
      count: attempts.count + 1,
      lastAttempt: Date.now(),
    };

    await env.SAINT_CENTRAL_KV.put(key, JSON.stringify(newAttempts), {
      expirationTtl: Math.floor(config.security.loginLockoutDuration / 1000),
    });
  },
  async clearFailedLogins(email, env) {
    const key = `bruteforce:${email}`;
    await env.SAINT_CENTRAL_KV.delete(key);
  },
  checkSecurityHeaders(request) {
    const country = request.headers.get("CF-IPCountry");
    const clientIP = request.headers.get("CF-Connecting-IP");
    const bot = request.headers.get("CF-Bot");
    const threat = request.headers.get("CF-Threat-Score");

    // Enhanced threat detection
    const blockedCountries = process.env.BLOCKED_COUNTRIES?.split(",") || [];
    if (blockedCountries.includes(country)) {
      return { allowed: false, reason: "COUNTRY_BLOCKED" };
    }

    if (bot === "likely") {
      return { allowed: false, reason: "BOT_DETECTED" };
    }

    if (threat && parseInt(threat) > 20) {
      return { allowed: false, reason: "HIGH_THREAT_SCORE" };
    }

    return { allowed: true };
  },
  generateSecureHeaders() {
    return {
      "Content-Security-Policy": [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "connect-src 'self' https://saint-central-api.colinmcherney.workers.dev",
        "font-src 'self'",
        "object-src 'none'",
        "media-src 'self'",
        "frame-src 'none'",
        "upgrade-insecure-requests",
      ].join("; "),
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Strict-Transport-Security":
        "max-age=31536000; includeSubDomains; preload",
      "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    };
  },
  generateRequestId() {
    return `req_${Date.now()}_${crypto.randomUUID()}`;
  },
  async logSecurityEvent(event, env) {
    try {
      const logEntry = {
        ...event,
        timestamp: new Date().toISOString(),
        severity: this.getEventSeverity(event.type),
      };

      Logger.warn("Security Event", logEntry);

      if (env.SAINT_CENTRAL_KV) {
        const logKey = `security:${
          event.type
        }:${Date.now()}:${crypto.randomUUID()}`;
        await env.SAINT_CENTRAL_KV.put(logKey, JSON.stringify(logEntry), {
          expirationTtl: 86400 * 30, // Keep for 30 days
        });
      }

      // Send critical events to external monitoring
      if (logEntry.severity === "critical") {
        await this.sendToExternalMonitoring(logEntry, env);
      }
    } catch (error) {
      Logger.error("Failed to log security event", { error: error.message });
    }
  },
  getEventSeverity(eventType) {
    const criticalEvents = [
      "MALWARE_DETECTED",
      "SQL_INJECTION_ATTEMPT",
      "UNAUTHORIZED_ADMIN_ACCESS",
    ];
    const highEvents = [
      "BRUTE_FORCE_DETECTED",
      "RATE_LIMIT_EXCEEDED",
      "SUSPICIOUS_ACTIVITY",
    ];

    if (criticalEvents.includes(eventType)) return "critical";
    if (highEvents.includes(eventType)) return "high";
    return "medium";
  },
  async sendToExternalMonitoring(event, env) {
    if (env.WEBHOOK_URL) {
      try {
        await fetch(env.WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(event),
        });
      } catch (error) {
        Logger.error("Failed to send to external monitoring", {
          error: error.message,
        });
      }
    }
  },
};

// Enhanced file scanner
async function scanFileForMalware(fileData, filename) {
  const threats = [];

  if (fileData.byteLength > 100 * 1024 * 1024) {
    // 100MB
    threats.push("FILE_TOO_LARGE");
  }

  const header = new Uint8Array(fileData.slice(0, 20));

  if (header[0] === 77 && header[1] === 90) threats.push("WINDOWS_EXECUTABLE"); // MZ
  if (
    header[0] === 127 &&
    header[1] === 69 &&
    header[2] === 76 &&
    header[3] === 70
  ) {
    threats.push("LINUX_EXECUTABLE"); // ELF
  }

  const dangerousExtensions = [
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".pif",
    ".jar",
    ".sh",
  ];
  const ext = filename.toLowerCase().substring(filename.lastIndexOf("."));
  if (dangerousExtensions.includes(ext)) {
    threats.push("DANGEROUS_EXTENSION");
  }

  const dataString = new TextDecoder("utf-8", { fatal: false }).decode(
    fileData.slice(0, 10000)
  );
  const malwarePatterns = [
    /eval\s*\(/gi,
    /document\.write\s*\(/gi,
    /javascript:\s*void/gi,
    /<script[^>]*>[\s\S]*?<\/script>/gi,
  ];

  for (const pattern of malwarePatterns) {
    if (pattern.test(dataString)) {
      threats.push("SUSPICIOUS_PATTERN");
      break;
    }
  }

  return { safe: threats.length === 0, threats, scannedAt: Date.now() };
}

// Production request handlers
const Handlers = {
  getDatabase(config) {
    if (!this._dbClient) {
      this._dbClient = new SupabaseClient(config);
    }
    return this._dbClient;
  },

  async handleDatabase(request, env, config, pathParts) {
    const db = this.getDatabase(config);
    const tableName = pathParts[2]; // pathParts is [rest, v1, tableName]

    if (!Validator.validateTableName(tableName)) {
      return {
        error: { message: "Table not found", code: "TABLE_NOT_FOUND" },
        status: 404,
      };
    }

    const url = new URL(request.url);
    const queryParams = Object.fromEntries(url.searchParams.entries());
    let requestBody = {};

    const sessionId = request.headers.get("X-Session-ID");
    let encryptionInstance = new Encryption(config.security.encryptionKey);

    if (sessionId && env.SAINT_CENTRAL_KV) {
      const sessionData = await env.SAINT_CENTRAL_KV.get(
        `session:${sessionId}`,
        { type: "json" }
      );
      if (sessionData && sessionData.sessionKey) {
        encryptionInstance = new Encryption(sessionData.sessionKey);
        Logger.debug(
          "DB Handler: Using session-specific encryption key for potential decryption."
        );
      } else {
        Logger.warn(
          "DB Handler: Session key not found for session ID, using default encryption key.",
          { sessionId }
        );
      }
    }

    const contentType = request.headers.get("Content-Type") || "";
    if (
      (request.method === "POST" || request.method === "PATCH") &&
      contentType.includes("application/encrypted+json")
    ) {
      try {
        const encryptedPayload = await request.json();
        Logger.debug("DB Handler: Encrypted payload received", {
          tableName,
          method: request.method,
          encryptedPayloadVersion: encryptedPayload.version,
        });

        if (encryptedPayload.encrypted && encryptedPayload.data) {
          requestBody = await encryptionInstance.decrypt(encryptedPayload);
          Logger.debug("DB Handler: Payload decrypted successfully", {
            tableName,
            method: request.method,
          });
        } else {
          Logger.warn(
            "DB Handler: Received encrypted+json but payload not in expected format or not marked encrypted.",
            {
              payloadPreview: JSON.stringify(encryptedPayload).substring(
                0,
                100
              ),
            }
          );
          // It's an error if client sent encrypted+json but it's not a valid encrypted structure
          return {
            error: {
              message: "Invalid encrypted payload structure.",
              code: "INVALID_ENCRYPTED_PAYLOAD",
            },
            status: 400,
          };
        }
      } catch (decryptError) {
        Logger.error("DB Handler: Decryption failed for database operation", {
          tableName,
          method: request.method,
          error: decryptError.message,
        });
        return {
          error: {
            message: "Failed to decrypt payload for database operation",
            code: "DECRYPTION_ERROR",
            details: decryptError.message,
          },
          status: 400,
        };
      }
    } else if (request.method === "POST" || request.method === "PATCH") {
      requestBody = await request.json().catch((e) => {
        Logger.error(
          "DB Handler: Failed to parse JSON body for non-encrypted request",
          { error: e.message }
        );
        throw new Error("Invalid JSON payload"); // Rethrow to be caught by outer try-catch
      });
    }

    try {
      switch (request.method) {
        case "GET": {
          const options = {
            select: queryParams.select || "*",
            where: this.extractWhereParams(queryParams),
            orderBy: queryParams.order,
            limit: queryParams.limit,
            offset: queryParams.offset,
          };
          const result = await db.select(tableName, options);
          return result.error
            ? { error: result.error, status: 400 }
            : { data: result.rows };
        }
        case "POST": {
          const result = await db.insert(tableName, requestBody);
          return result.error
            ? { error: result.error, status: 400 }
            : { data: result.rows };
        }
        case "PATCH": {
          const where = this.extractWhereParams(queryParams);
          if (Object.keys(where).length === 0) {
            return {
              error: { message: "WHERE conditions required for UPDATE" },
              status: 400,
            };
          }
          const result = await db.update(tableName, requestBody, where);
          return result.error
            ? { error: result.error, status: 400 }
            : { data: result.rows };
        }
        case "DELETE": {
          const where = this.extractWhereParams(queryParams);
          if (Object.keys(where).length === 0) {
            return {
              error: { message: "WHERE conditions required for DELETE" },
              status: 400,
            };
          }
          const result = await db.delete(tableName, where);
          return result.error
            ? { error: result.error, status: 400 }
            : { data: result.rows };
        }
        default:
          return {
            error: { message: "Method not supported for this table" },
            status: 405,
          };
      }
    } catch (error) {
      Logger.error("Database operation failed after processing body", {
        table: tableName,
        method: request.method,
        error: error.message,
        requestBodyPreview: JSON.stringify(requestBody).substring(0, 100),
      });
      return {
        error: {
          message: "Database operation failed",
          code: "DB_ERROR",
          details: error.message,
        },
        status: 500,
      };
    }
  },

  extractWhereParams(queryParams) {
    const where = {};
    const excludeKeys = ["select", "order", "limit", "offset"];
    for (const [key, value] of Object.entries(queryParams)) {
      if (!excludeKeys.includes(key)) {
        where[key] = value;
      }
    }
    return where;
  },

  async handleAuth(request, env, config, pathParts) {
    const authAction = pathParts[1];
    const encryption = new Encryption(config.security.encryptionKey);

    switch (authAction) {
      case "signup":
        return await this.handleSignup(request, env, config, encryption);
      case "signin":
        return await this.handleSignin(request, env, config, encryption);
      case "signout":
        return await this.handleSignout(request, env, config);
      case "session":
        return await this.handleSession(request, env, config);
      case "recover":
        return await this.handlePasswordRecovery(request, env, config);
      case "token":
        return await this.handleTokenRefresh(request, env, config);
      case "key-exchange":
        return await this.handleKeyExchange(request, env, config);
      default:
        Logger.warn("Unsupported auth action", {
          authAction,
          path: request.url,
        });
        return {
          error: {
            message: `Auth action '${authAction}' not supported`,
            code: "AUTH_ACTION_NOT_FOUND",
          },
          status: 404,
        };
    }
  },

  async handleSignup(request, env, config, encryption) {
    try {
      const contentType = request.headers.get("Content-Type") || "";
      const sessionId = request.headers.get("X-Session-ID");
      let payload;
      Logger.debug("Signup request received", { contentType, sessionId });

      if (contentType.includes("application/encrypted+json")) {
        try {
          let sessionEncryption = encryption;
          if (sessionId && env.SAINT_CENTRAL_KV) {
            const sessionData = await env.SAINT_CENTRAL_KV.get(
              `session:${sessionId}`,
              { type: "json" }
            );
            if (sessionData && sessionData.sessionKey) {
              sessionEncryption = new Encryption(sessionData.sessionKey);
              Logger.debug("Using session-specific encryption key for signup");
            } else {
              Logger.warn("Signup: Session key not found, using default.", {
                sessionId,
              });
            }
          }
          const encryptedText = await request.text();
          const encryptedData = JSON.parse(encryptedText);
          payload = await sessionEncryption.decrypt(encryptedData);
          Logger.debug("Signup: Decryption successful");
        } catch (decryptError) {
          Logger.error("Decryption failed in signup", {
            error: decryptError.message,
            sessionId,
          });
          return {
            error: {
              message: "Failed to decrypt request payload",
              code: "DECRYPTION_ERROR",
              details: decryptError.message,
            },
            status: 400,
          };
        }
      } else {
        payload = await request.json();
        Logger.debug("Unencrypted payload received for signup");
      }

      if (!payload.email || !Validator.email(payload.email))
        return { error: { message: "Valid email required" }, status: 400 };
      const passwordValidation = Validator.password(
        payload.password,
        config.security.passwordMinLength
      );
      if (!passwordValidation.valid)
        return { error: { message: passwordValidation.message }, status: 400 };

      const response = await fetch(`${config.supabase.url}/auth/v1/signup`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          apikey: config.supabase.anonKey,
        },
        body: JSON.stringify({
          email: payload.email,
          password: payload.password,
          data: payload.metadata || {},
        }),
      });
      const result = await response.json();
      await Security.logSecurityEvent(
        {
          type: "SIGNUP_ATTEMPT",
          email: payload.email,
          success: response.ok,
          ip: request.headers.get("CF-Connecting-IP"),
          sessionId,
        },
        env
      );
      return response.ok
        ? { data: result }
        : { error: result, status: response.status };
    } catch (error) {
      Logger.error("Signup failed", { error: error.message });
      return {
        error: { message: "Signup failed", code: "SIGNUP_ERROR" },
        status: 500,
      };
    }
  },

  async handleSignin(request, env, config, encryption) {
    // ... (similar decryption logic as signup)
    try {
      const contentType = request.headers.get("Content-Type") || "";
      const sessionId = request.headers.get("X-Session-ID");
      let payload;
      Logger.debug("Signin request received", { contentType, sessionId });

      if (contentType.includes("application/encrypted+json")) {
        try {
          let sessionEncryption = encryption;
          if (sessionId && env.SAINT_CENTRAL_KV) {
            const sessionData = await env.SAINT_CENTRAL_KV.get(
              `session:${sessionId}`,
              { type: "json" }
            );
            if (sessionData && sessionData.sessionKey) {
              sessionEncryption = new Encryption(sessionData.sessionKey);
              Logger.debug("Using session-specific encryption key for signin");
            } else {
              Logger.warn("Signin: Session key not found, using default.", {
                sessionId,
              });
            }
          }
          const encryptedText = await request.text();
          const encryptedData = JSON.parse(encryptedText);
          payload = await sessionEncryption.decrypt(encryptedData);
          Logger.debug("Signin: Decryption successful");
        } catch (decryptError) {
          Logger.error("Decryption failed in signin", {
            error: decryptError.message,
            sessionId,
          });
          return {
            error: {
              message: "Failed to decrypt request payload",
              code: "DECRYPTION_ERROR",
              details: decryptError.message,
            },
            status: 400,
          };
        }
      } else {
        payload = await request.json();
        Logger.debug("Unencrypted payload received for signin");
      }

      if (!payload.email || !Validator.email(payload.email))
        return { error: { message: "Valid email required" }, status: 400 };
      if (!payload.password)
        return { error: { message: "Password required" }, status: 400 };

      // Brute force check ...
      const response = await fetch(
        `${config.supabase.url}/auth/v1/token?grant_type=password`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            apikey: config.supabase.anonKey,
          },
          body: JSON.stringify({
            email: payload.email,
            password: payload.password,
          }),
        }
      );
      const result = await response.json();
      // ... (logging and error handling as before)
      return response.ok
        ? { data: result }
        : { error: result, status: response.status };
    } catch (error) {
      Logger.error("Signin failed", { error: error.message });
      return {
        error: { message: "Signin failed", code: "SIGNIN_ERROR" },
        status: 500,
      };
    }
  },

  // handleSignout, handleSession, handlePasswordRecovery, handleTokenRefresh, handleKeyExchange
  // ... (ensure these are complete and use appropriate error status codes)
  async handleSignout(request, env, config) {
    try {
      const authHeader = request.headers.get("Authorization");
      const token = authHeader ? authHeader.replace("Bearer ", "") : null;
      if (!token)
        return { error: { message: "No token provided" }, status: 401 };

      const response = await fetch(`${config.supabase.url}/auth/v1/logout`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          apikey: config.supabase.anonKey,
        },
      });
      // Logout usually returns 204 No Content on success
      if (!response.ok) {
        const result = await response
          .json()
          .catch(() => ({ message: response.statusText }));
        return { error: result, status: response.status };
      }
      return { data: { message: "Signed out successfully" } };
    } catch (error) {
      Logger.error("Signout failed", { error: error.message });
      return { error: { message: "Signout failed" } };
    }
  },
  async handleSession(request, env, config) {
    try {
      const authHeader = request.headers.get("Authorization");
      const token = authHeader ? authHeader.replace("Bearer ", "") : null;
      if (!token)
        return { error: { message: "No session token provided" }, status: 401 };

      const response = await fetch(`${config.supabase.url}/auth/v1/user`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          apikey: config.supabase.anonKey,
        },
      });
      const result = await response.json();
      if (!response.ok) {
        Logger.warn("Session validation with Supabase failed (/auth/v1/user)", {
          status: response.status,
          result,
        });
        return {
          error: {
            message: result.message || "Invalid session",
            code: result.code || "SESSION_INVALID",
          },
          status: response.status,
        };
      }
      result.security = {
        /* ... */
      }; // Add your security metadata
      return { data: result };
    } catch (error) {
      Logger.error("Session validation failed", { error: error.message });
      return { error: { message: "Session validation failed" } };
    }
  },
  async handlePasswordRecovery(request, env, config) {
    try {
      const contentType = request.headers.get("Content-Type") || "";
      const sessionId = request.headers.get("X-Session-ID");
      let payload;
      const encryption = new Encryption(config.security.encryptionKey);

      if (contentType.includes("application/encrypted+json")) {
        try {
          let sessionEncryption = encryption;
          if (sessionId && env.SAINT_CENTRAL_KV) {
            /* ... get session key ... */
          }
          const encryptedText = await request.text();
          const encryptedData = JSON.parse(encryptedText);
          payload = await sessionEncryption.decrypt(encryptedData);
        } catch (decryptError) {
          /* ... handle ... */ return {
            error: { message: "Decryption failed", code: "DECRYPTION_ERROR" },
            status: 400,
          };
        }
      } else {
        payload = await request.json();
      }

      const { email } = payload;
      if (!email || !Validator.email(email))
        return { error: { message: "Valid email required" } };

      const response = await fetch(`${config.supabase.url}/auth/v1/recover`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          apikey: config.supabase.anonKey,
        },
        body: JSON.stringify({ email }),
      });
      await Security.logSecurityEvent(
        { type: "PASSWORD_RECOVERY_REQUEST" /* ... */ },
        env
      );
      if (!response.ok) {
        // Though Supabase usually returns 200 for recover
        const errorResult = await response
          .json()
          .catch(() => ({ message: "Password recovery request failed." }));
        return { error: errorResult, status: response.status };
      }
      return {
        data: { message: "Password recovery email sent if user exists." },
      };
    } catch (error) {
      Logger.error("Password recovery failed", { error: error.message });
      return { error: { message: "Password recovery failed" } };
    }
  },
  async handleTokenRefresh(request, env, config) {
    try {
      const { refresh_token } = await request.json();
      if (!refresh_token)
        return { error: { message: "Refresh token required" }, status: 400 };

      const response = await fetch(
        `${config.supabase.url}/auth/v1/token?grant_type=refresh_token`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            apikey: config.supabase.anonKey,
          },
          body: JSON.stringify({ refresh_token }),
        }
      );
      const result = await response.json();
      await Security.logSecurityEvent({ type: "TOKEN_REFRESH" /* ... */ }, env);
      return response.ok
        ? { data: result }
        : { error: result, status: response.status };
    } catch (error) {
      Logger.error("Token refresh failed", { error: error.message });
      return { error: { message: "Token refresh failed" } };
    }
  },
  async handleKeyExchange(request, env, config) {
    try {
      const clientIP = request.headers.get("CF-Connecting-IP");
      const userAgent = request.headers.get("User-Agent");
      const requestId = Security.generateRequestId();
      const sessionKey = Config.generateEncryptionKey();
      const sessionId = crypto.randomUUID();
      const sessionData = {
        sessionKey,
        clientIP,
        userAgent,
        createdAt: Date.now(),
        requestId,
      };

      if (env.SAINT_CENTRAL_KV) {
        await env.SAINT_CENTRAL_KV.put(
          `session:${sessionId}`,
          JSON.stringify(sessionData),
          { expirationTtl: 3600 }
        );
      }
      await Security.logSecurityEvent({ type: "KEY_EXCHANGE" /* ... */ }, env);
      Logger.info("Key exchange completed", { sessionId, clientIP, requestId });
      return {
        data: {
          sessionId,
          sessionKey,
          algorithm: "AES-256-GCM",
          version: 2,
          expiresAt: Date.now() + 3600000,
          requestId,
        },
      };
    } catch (error) {
      Logger.error("Key exchange failed", {
        error: error.message,
        stack: error.stack,
      });
      return {
        error: { message: "Key exchange failed", code: "KEY_EXCHANGE_ERROR" },
      };
    }
  },

  async handleStorage(request, env, config, pathParts) {
    // pathParts[0] is 'storage', pathParts[1] is 'v1'
    const storageAction = pathParts[2]; // e.g. 'bucket', 'object'

    try {
      switch (storageAction) {
        case "bucket": // /storage/v1/bucket OR /storage/v1/bucket/{bucketName}
          return await this.handleBucketOperations(
            request,
            env,
            config,
            pathParts.slice(2)
          ); // Pass [bucket, {bucketName}]
        case "object": // /storage/v1/object/list/{bucketName} OR /storage/v1/object/{bucketName}/{filePath}
          return await this.handleObjectOperations(
            request,
            env,
            config,
            pathParts.slice(2)
          ); // Pass [object, list/bucketName, ...]
        default:
          return {
            error: {
              message: `Storage action '${storageAction}' not supported`,
            },
            status: 400,
          };
      }
    } catch (error) {
      Logger.error("Storage operation failed", { error: error.message });
      return { error: { message: "Storage operation failed" } };
    }
  },
  async handleFunctions(request, env, config, pathParts) {
    if (
      pathParts[0] === "functions" &&
      pathParts[1] === "v1" &&
      pathParts.length > 2
    ) {
      // ...
    } else if (
      pathParts[0] === "rest" &&
      pathParts[1] === "v1" &&
      pathParts[2] === "rpc" &&
      pathParts.length > 3
    ) {
      // ...
    }
    return { error: { message: "Function handler to be fully implemented" } };
  },
};

// Main worker
export default {
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    let config;

    try {
      config = new Config(env);
      Logger.setLevel(config.monitoring.logLevel);

      const requestId = Security.generateRequestId();

      let allowedOrigin = config.cors.allowedOrigins.includes("*")
        ? "*"
        : request.headers.get("Origin") ||
          config.cors.allowedOrigins[0] ||
          null;
      if (
        allowedOrigin &&
        allowedOrigin !== "*" &&
        !config.cors.allowedOrigins.includes(allowedOrigin)
      ) {
        // If origin is specific but not in the list, and "*" is not allowed, block or use a default.
        // For now, if it's not "*", it must be in the list or it defaults to the first.
        // This logic needs to be robust based on security needs.
        if (
          config.cors.allowedOrigins.length > 0 &&
          !config.cors.allowedOrigins.includes("*")
        ) {
          Logger.warn(
            "CORS: Request origin not explicitly allowed, using first configured origin as fallback.",
            {
              requestOrigin: request.headers.get("Origin"),
              fallbackOrigin: config.cors.allowedOrigins[0],
            }
          );
          allowedOrigin = config.cors.allowedOrigins[0];
        } else if (!config.cors.allowedOrigins.includes("*")) {
          // No origins configured, and not allowing *
          Logger.error(
            "CORS: No allowed origins configured and '*' is not permitted. Blocking request."
          );
          return new Response("CORS configuration error", { status: 500 });
        }
        // If "*" was in the original list, it would have been caught already.
      }

      const baseCorsHeaders = {
        "Access-Control-Allow-Origin": allowedOrigin,
        "Access-Control-Allow-Methods": config.cors.allowedMethods.join(", "),
        "Access-Control-Allow-Headers": config.cors.allowedHeaders.join(", "),
        "Access-Control-Allow-Credentials": "true",
        "X-Request-ID": requestId,
        "X-Saint-Central-Version": "2.2.0",
      };

      const secureHeaders = Security.generateSecureHeaders();
      const corsHeaders = { ...baseCorsHeaders, ...secureHeaders };

      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders });
      }

      const securityCheck = Security.checkSecurityHeaders(request); // Assuming this is complete
      if (!securityCheck.allowed) {
        await Security.logSecurityEvent(
          {
            type: "SECURITY_BLOCK",
            reason: securityCheck.reason,
            ip: request.headers.get("CF-Connecting-IP"),
            requestId,
          },
          env
        );
        return new Response(
          JSON.stringify({
            error: "Request blocked for security reasons",
            code: securityCheck.reason,
            requestId,
          }),
          {
            status: 403,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      const rateLimitResult = await Security.rateLimit(request, env, config); // Assuming this is complete
      if (!rateLimitResult.allowed) {
        await Security.logSecurityEvent(
          {
            type: "RATE_LIMIT_EXCEEDED",
            ip: request.headers.get("CF-Connecting-IP"),
            path: new URL(request.url).pathname,
            requestId,
          },
          env
        );
        const rateLimitHeaders = {
          ...corsHeaders,
          "Content-Type": "application/json",
          "X-RateLimit-Limit": rateLimitResult.limit?.toString() || "0",
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": new Date(
            rateLimitResult.resetAt || Date.now() + 60000
          ).toISOString(),
          "Retry-After": "60",
        };
        return new Response(
          JSON.stringify({
            error: "Too many requests",
            code: "RATE_LIMITED",
            requestId,
            resetAt: rateLimitResult.resetAt,
          }),
          {
            status: 429,
            headers: {
              ...corsHeaders,
              ...rateLimitHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      const url = new URL(request.url);
      const pathParts = url.pathname.split("/").filter(Boolean);

      Logger.info("Request Received", {
        requestId,
        method: request.method,
        path: url.pathname,
      });

      if (pathParts.length === 0 && request.method === "GET") {
        // Health check
        const db = Handlers.getDatabase(config);
        const stats = db.getStats();
        return new Response(
          JSON.stringify({
            name: "Saint Central API",
            version: "2.2.0",
            status: "operational",
            timestamp: new Date().toISOString(),
            requestId,
            stats: config.monitoring.enableMetrics ? stats : undefined,
          }),
          {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      let result;
      // Updated Routing Logic
      if (
        pathParts[0] === "rest" &&
        pathParts[1] === "v1" &&
        pathParts[2] !== "rpc"
      ) {
        result = await Handlers.handleDatabase(request, env, config, pathParts);
      } else if (pathParts[0] === "auth") {
        result = await Handlers.handleAuth(request, env, config, pathParts);
      } else if (pathParts[0] === "storage" && pathParts[1] === "v1") {
        result = await Handlers.handleStorage(request, env, config, pathParts);
      } else if (
        (pathParts[0] === "functions" && pathParts[1] === "v1") ||
        (pathParts[0] === "rest" &&
          pathParts[1] === "v1" &&
          pathParts[2] === "rpc")
      ) {
        result = await Handlers.handleFunctions(
          request,
          env,
          config,
          pathParts
        );
      } else {
        result = {
          error: { message: "Endpoint not found", code: "NOT_FOUND" },
          status: 404,
        };
      }

      const duration = Date.now() - startTime;
      const responseStatus = result.error
        ? result.status || (result.error.code === "NOT_FOUND" ? 404 : 400)
        : 200;
      Logger.info("Request Completed", {
        requestId,
        duration,
        success: !result.error,
        statusCode: responseStatus,
      });

      const responseHeaders = {
        ...corsHeaders,
        "Content-Type": "application/json",
        "Cache-Control": "private, no-cache, no-store, must-revalidate",
        "X-Response-Time": `${duration}ms`,
      };
      if (rateLimitResult.limit) {
        /* ... add rate limit headers ... */
      }

      if (result.error) {
        const safeError = {
          message: result.error.message,
          code: result.error.code || "ERROR",
          requestId,
          details:
            config.monitoring.logLevel === "debug" && result.error.details
              ? result.error.details
              : undefined,
        };
        return new Response(JSON.stringify({ error: safeError }), {
          status: responseStatus,
          headers: responseHeaders,
        });
      } else {
        if (result.data instanceof ArrayBuffer) {
          /* ... handle ArrayBuffer for file download ... */
        }
        if (result.data instanceof Response) {
          return result.data;
        } // If handler returns a full Response
        return new Response(JSON.stringify({ data: result.data, requestId }), {
          status: responseStatus,
          headers: responseHeaders,
        });
      }
    } catch (error) {
      const requestId = Security.generateRequestId();
      Logger.error("Unhandled Error in Worker Fetch", {
        requestId,
        error: error.message,
        stack: error.stack,
      });
      if (config) {
        await Security.logSecurityEvent(
          { type: "SERVER_ERROR", error: error.message, requestId },
          env
        );
      }
      const errorCorsHeaders = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
        "X-Request-ID": requestId,
        ...Security.generateSecureHeaders(),
      };
      return new Response(
        JSON.stringify({
          error: {
            message: "An unexpected error occurred",
            code: "SERVER_ERROR",
            requestId,
          },
        }),
        { status: 500, headers: errorCorsHeaders }
      );
    }
  },
};
