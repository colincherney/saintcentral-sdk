/**
 * Saint Central Cloudflare Worker - Production Ready
 *
 * Enterprise-grade secure middleware with direct PostgreSQL connections,
 * comprehensive security, monitoring, and error handling.
 *
 * @version 2.0.0
 * @author Saint Central Security Team
 */

import { neon } from "@neondatabase/serverless";

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

// Production-grade PostgreSQL client
class PostgresClient {
  constructor(config) {
    this.config = config;
    this.sql = neon(config.database.url);
    this.connectionPool = new Map();
    this.queryStats = {
      totalQueries: 0,
      totalDuration: 0,
      errors: 0,
    };
  }

  async query(sql, params = [], options = {}) {
    const startTime = Date.now();
    const queryId = this.generateQueryId();

    try {
      this.logQuery(queryId, sql, params);

      // Set query timeout
      const timeout = options.timeout || this.config.database.queryTimeout;
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error("Query timeout")), timeout);
      });

      const queryPromise = this.sql(sql, params);
      const result = await Promise.race([queryPromise, timeoutPromise]);

      const duration = Date.now() - startTime;
      this.updateQueryStats(true, duration);
      this.logQueryResult(queryId, duration, result.length);

      return { rows: result, error: null };
    } catch (error) {
      const duration = Date.now() - startTime;
      this.updateQueryStats(false, duration);
      this.logQueryError(queryId, error, duration);

      // Sanitize error for production
      const sanitizedError = this.sanitizeError(error);
      return { rows: null, error: sanitizedError };
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

  logQuery(queryId, sql, params) {
    Logger.debug("Database Query", {
      queryId,
      sql: sql.substring(0, 200) + (sql.length > 200 ? "..." : ""),
      paramCount: params.length,
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
      error: error.message,
      duration,
    });
  }

  sanitizeError(error) {
    // Remove sensitive information from error messages
    const message = error.message
      .replace(/password\s*=\s*[^\s]+/gi, "password=***")
      .replace(/key\s*=\s*[^\s]+/gi, "key=***");

    return {
      message: "Database operation failed",
      code: "DB_ERROR",
      details: process.env.NODE_ENV === "development" ? message : undefined,
    };
  }

  buildSelectQuery(tableName, options = {}) {
    const {
      select = "*",
      where = {},
      orderBy,
      limit,
      offset,
      joins = [],
    } = options;

    let sql = `SELECT ${this.sanitizeSelectFields(
      select
    )} FROM ${this.sanitizeIdentifier(tableName)}`;
    const params = [];
    let paramIndex = 1;

    // Add JOINs
    joins.forEach((join) => {
      sql += ` ${join.type || "INNER"} JOIN ${this.sanitizeIdentifier(
        join.table
      )} ON ${join.condition}`;
    });

    // Add WHERE clause
    const { whereClause, whereParams } = this.buildWhereClause(
      where,
      paramIndex
    );
    if (whereClause) {
      sql += ` WHERE ${whereClause}`;
      params.push(...whereParams);
      paramIndex += whereParams.length;
    }

    // Add ORDER BY
    if (orderBy) {
      const orderClauses = Array.isArray(orderBy) ? orderBy : [orderBy];
      const sanitizedOrder = orderClauses.map((order) => {
        const [column, direction] = order.split(".");
        return `${this.sanitizeIdentifier(column)} ${
          direction === "desc" ? "DESC" : "ASC"
        }`;
      });
      sql += ` ORDER BY ${sanitizedOrder.join(", ")}`;
    }

    // Add LIMIT and OFFSET
    if (limit) {
      sql += ` LIMIT $${paramIndex}`;
      params.push(parseInt(limit));
      paramIndex++;
    }

    if (offset) {
      sql += ` OFFSET $${paramIndex}`;
      params.push(parseInt(offset));
    }

    return { sql, params };
  }

  buildInsertQuery(tableName, data, returning = "*") {
    // Handle both single objects and arrays
    const rows = Array.isArray(data) ? data : [data];

    if (rows.length === 0) {
      throw new Error("No data provided for insert");
    }

    // Get columns from the first row
    const columns = Object.keys(rows[0]);
    const allParams = [];
    const valueGroups = [];
    let paramIndex = 1;

    // Build value groups for each row
    for (const row of rows) {
      const rowValues = columns.map((col) => row[col]);
      const placeholders = rowValues.map(() => `$${paramIndex++}`);
      valueGroups.push(`(${placeholders.join(", ")})`);
      allParams.push(...rowValues);
    }

    const sql = `
      INSERT INTO ${this.sanitizeIdentifier(tableName)} 
      (${columns.map((col) => this.sanitizeIdentifier(col)).join(", ")}) 
      VALUES ${valueGroups.join(", ")} 
      RETURNING ${this.sanitizeSelectFields(returning)}
    `;

    return { sql, params: allParams };
  }

  buildUpdateQuery(tableName, data, where, returning = "*") {
    const setClauses = [];
    const params = [];
    let paramIndex = 1;

    // Build SET clause
    for (const [key, value] of Object.entries(data)) {
      setClauses.push(`${this.sanitizeIdentifier(key)} = $${paramIndex}`);
      params.push(value);
      paramIndex++;
    }

    // Build WHERE clause
    const { whereClause, whereParams } = this.buildWhereClause(
      where,
      paramIndex
    );
    if (!whereClause) {
      throw new Error("WHERE clause required for UPDATE operations");
    }

    params.push(...whereParams);

    const sql = `
      UPDATE ${this.sanitizeIdentifier(tableName)} 
      SET ${setClauses.join(", ")} 
      WHERE ${whereClause} 
      RETURNING ${this.sanitizeSelectFields(returning)}
    `;

    return { sql, params };
  }

  buildDeleteQuery(tableName, where, returning = "*") {
    const { whereClause, whereParams } = this.buildWhereClause(where, 1);
    if (!whereClause) {
      throw new Error("WHERE clause required for DELETE operations");
    }

    const sql = `
      DELETE FROM ${this.sanitizeIdentifier(tableName)} 
      WHERE ${whereClause} 
      RETURNING ${this.sanitizeSelectFields(returning)}
    `;

    return { sql, params: whereParams };
  }

  buildWhereClause(where, startParamIndex = 1) {
    const conditions = [];
    const params = [];
    let paramIndex = startParamIndex;

    for (const [key, value] of Object.entries(where)) {
      if (typeof value === "string" && value.includes(".")) {
        const [operator, filterValue] = value.split(".", 2);

        switch (operator) {
          case "eq":
            conditions.push(`${this.sanitizeIdentifier(key)} = $${paramIndex}`);
            params.push(filterValue);
            paramIndex++;
            break;
          case "neq":
            conditions.push(
              `${this.sanitizeIdentifier(key)} != $${paramIndex}`
            );
            params.push(filterValue);
            paramIndex++;
            break;
          case "gt":
            conditions.push(`${this.sanitizeIdentifier(key)} > $${paramIndex}`);
            params.push(filterValue);
            paramIndex++;
            break;
          case "gte":
            conditions.push(
              `${this.sanitizeIdentifier(key)} >= $${paramIndex}`
            );
            params.push(filterValue);
            paramIndex++;
            break;
          case "lt":
            conditions.push(`${this.sanitizeIdentifier(key)} < $${paramIndex}`);
            params.push(filterValue);
            paramIndex++;
            break;
          case "lte":
            conditions.push(
              `${this.sanitizeIdentifier(key)} <= $${paramIndex}`
            );
            params.push(filterValue);
            paramIndex++;
            break;
          case "like":
            conditions.push(
              `${this.sanitizeIdentifier(key)} LIKE $${paramIndex}`
            );
            params.push(filterValue);
            paramIndex++;
            break;
          case "ilike":
            conditions.push(
              `${this.sanitizeIdentifier(key)} ILIKE $${paramIndex}`
            );
            params.push(filterValue);
            paramIndex++;
            break;
          case "in":
            const inValues = filterValue.split(",");
            const placeholders = inValues
              .map(() => `$${paramIndex++}`)
              .join(",");
            conditions.push(
              `${this.sanitizeIdentifier(key)} IN (${placeholders})`
            );
            params.push(...inValues);
            break;
          case "is":
            if (filterValue.toLowerCase() === "null") {
              conditions.push(`${this.sanitizeIdentifier(key)} IS NULL`);
            } else {
              conditions.push(
                `${this.sanitizeIdentifier(key)} IS $${paramIndex}`
              );
              params.push(filterValue);
              paramIndex++;
            }
            break;
        }
      } else {
        // Default to equality
        conditions.push(`${this.sanitizeIdentifier(key)} = $${paramIndex}`);
        params.push(value);
        paramIndex++;
      }
    }

    return {
      whereClause: conditions.join(" AND "),
      whereParams: params,
    };
  }

  sanitizeIdentifier(identifier) {
    // Allow only alphanumeric characters, underscores, and dots (for joins)
    const sanitized = identifier.replace(/[^a-zA-Z0-9_.]/g, "");

    // Validate against known patterns
    if (!/^[a-zA-Z][a-zA-Z0-9_.]*$/.test(sanitized)) {
      throw new Error(`Invalid identifier: ${identifier}`);
    }

    return sanitized;
  }

  sanitizeSelectFields(fields) {
    if (fields === "*") return "*";

    const fieldArray = Array.isArray(fields) ? fields : fields.split(",");
    return fieldArray
      .map((field) => field.trim())
      .map((field) => {
        // Handle aggregate functions and aliases
        if (
          field.includes("(") ||
          field.includes(" as ") ||
          field.includes(" AS ")
        ) {
          return field; // Allow complex expressions (validate separately if needed)
        }
        return this.sanitizeIdentifier(field);
      })
      .join(", ");
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

      // Generate a random IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Convert hex key to buffer (same as SDK)
      if (!/^[0-9a-fA-F]{64}$/.test(this.key)) {
        throw new Error(
          "Invalid encryption key format - must be 64-character hex string"
        );
      }

      const keyBuffer = new Uint8Array(
        this.key.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
      );

      // Import the key
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
      );

      // Encrypt the data
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        dataBuffer
      );

      // Combine IV and encrypted data
      const result = new Uint8Array(iv.length + encryptedBuffer.byteLength);
      result.set(iv, 0);
      result.set(new Uint8Array(encryptedBuffer), iv.length);

      // Convert to base64
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
        return encryptedData;
      }

      if (!encryptedData.encrypted || encryptedData.version !== 2) {
        return encryptedData;
      }

      const decoder = new TextDecoder();

      // Decode base64
      const combined = Uint8Array.from(atob(encryptedData.data), (c) =>
        c.charCodeAt(0)
      );

      // Extract IV and encrypted data
      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);

      // Convert hex key to buffer (same as SDK)
      if (!/^[0-9a-fA-F]{64}$/.test(this.key)) {
        throw new Error(
          "Invalid encryption key format - must be 64-character hex string"
        );
      }

      const keyBuffer = new Uint8Array(
        this.key.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
      );

      // Import the key
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // Decrypt the data
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        encrypted
      );

      // Convert back to string and parse JSON
      const decryptedString = decoder.decode(decryptedBuffer);
      return JSON.parse(decryptedString);
    } catch (error) {
      Logger.error("Decryption failed", {
        error: error.message,
        stack: error.stack,
        keyFormat: this.key ? "Present" : "Missing",
        keyLength: this.key?.length || 0,
      });
      throw new Error("Decryption failed");
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

      // Decode header and payload
      const header = JSON.parse(atob(headerB64));
      const payload = JSON.parse(atob(payloadB64));

      // Check expiration
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return null;
      }

      // Verify signature using Web Crypto API
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
    // Convert base64url to base64
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    // Add padding if needed
    while (str.length % 4) {
      str += "=";
    }
    // Decode base64
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

    return input.trim().slice(0, maxLength).replace(/[<>]/g, ""); // Basic XSS prevention
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

      if (!rateLimitData) {
        await env.SAINT_CENTRAL_KV.put(
          rateKey,
          JSON.stringify({ count: 1, resetAt: now + windowSize }),
          { expirationTtl: 60 }
        );
        return { allowed: true };
      }

      if (now > rateLimitData.resetAt) {
        await env.SAINT_CENTRAL_KV.put(
          rateKey,
          JSON.stringify({ count: 1, resetAt: now + windowSize }),
          { expirationTtl: 60 }
        );
        return { allowed: true };
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
      return { allowed: true }; // Fail open for availability
    }
  },

  getRateLimitForEndpoint(endpoint, method) {
    // Different rate limits for different endpoints
    if (endpoint.includes("/auth/signin")) return 10; // Stricter for login
    if (endpoint.includes("/auth/signup")) return 5; // Stricter for signup
    if (method === "POST") return 30;
    if (method === "GET") return 100;
    return 50; // Default
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
        "connect-src 'self'",
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
    // Integrate with external monitoring services
    // This is a placeholder for services like Datadog, Sentry, etc.
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

  // File size limits
  if (fileData.byteLength > 100 * 1024 * 1024) {
    // 100MB
    threats.push("FILE_TOO_LARGE");
  }

  // Header analysis
  const header = new Uint8Array(fileData.slice(0, 20));

  // Check for executable files
  if (header[0] === 77 && header[1] === 90) threats.push("WINDOWS_EXECUTABLE"); // MZ
  if (
    header[0] === 127 &&
    header[1] === 69 &&
    header[2] === 76 &&
    header[3] === 70
  ) {
    threats.push("LINUX_EXECUTABLE"); // ELF
  }

  // Check for script files by extension
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

  // Simple pattern matching for common malware signatures
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

  return {
    safe: threats.length === 0,
    threats,
    scannedAt: Date.now(),
  };
}

// Production request handlers
const Handlers = {
  // Initialize database client
  getDatabase(config) {
    if (!this._dbClient) {
      this._dbClient = new PostgresClient(config);
    }
    return this._dbClient;
  },

  // Handle database operations
  async handleDatabase(request, env, config, pathParts) {
    const db = this.getDatabase(config);
    const tableName = pathParts[2];

    // Validate table name
    if (!Validator.validateTableName(tableName)) {
      return { error: { message: "Table not found", code: "TABLE_NOT_FOUND" } };
    }

    const url = new URL(request.url);
    const queryParams = Object.fromEntries(url.searchParams.entries());

    try {
      switch (request.method) {
        case "GET": {
          const options = {
            select: queryParams.select || "*",
            where: this.extractWhereParams(queryParams),
            orderBy: queryParams.order,
            limit: queryParams.limit ? parseInt(queryParams.limit) : undefined,
            offset: queryParams.offset
              ? parseInt(queryParams.offset)
              : undefined,
          };

          const { sql, params } = db.buildSelectQuery(tableName, options);
          const result = await db.query(sql, params);

          return result.error ? { error: result.error } : { data: result.rows };
        }

        case "POST": {
          const body = await request.json();
          const { sql, params } = db.buildInsertQuery(
            tableName,
            body,
            queryParams.select
          );
          const result = await db.query(sql, params);

          return result.error ? { error: result.error } : { data: result.rows };
        }

        case "PATCH": {
          const body = await request.json();
          const where = this.extractWhereParams(queryParams);

          if (Object.keys(where).length === 0) {
            return {
              error: { message: "WHERE conditions required for UPDATE" },
            };
          }

          const { sql, params } = db.buildUpdateQuery(
            tableName,
            body,
            where,
            queryParams.select
          );
          const result = await db.query(sql, params);

          return result.error ? { error: result.error } : { data: result.rows };
        }

        case "DELETE": {
          const where = this.extractWhereParams(queryParams);

          if (Object.keys(where).length === 0) {
            return {
              error: { message: "WHERE conditions required for DELETE" },
            };
          }

          const { sql, params } = db.buildDeleteQuery(
            tableName,
            where,
            queryParams.select
          );
          const result = await db.query(sql, params);

          return result.error ? { error: result.error } : { data: result.rows };
        }

        default:
          return { error: { message: "Method not supported" } };
      }
    } catch (error) {
      Logger.error("Database operation failed", {
        table: tableName,
        method: request.method,
        error: error.message,
      });

      return {
        error: { message: "Database operation failed", code: "DB_ERROR" },
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

  // Handle authentication
  async handleAuth(request, env, config, pathParts) {
    const authAction = pathParts[1];
    const encryption = new Encryption(config.security.encryptionKey);

    switch (authAction) {
      case "signup": {
        return await this.handleSignup(request, env, config, encryption);
      }

      case "signin": {
        return await this.handleSignin(request, env, config, encryption);
      }

      case "signout": {
        return await this.handleSignout(request, env, config);
      }

      case "session": {
        return await this.handleSession(request, env, config);
      }

      case "recover": {
        return await this.handlePasswordRecovery(request, env, config);
      }

      case "token": {
        return await this.handleTokenRefresh(request, env, config);
      }

      case "key-exchange": {
        return await this.handleKeyExchange(request, env, config);
      }

      default:
        return { error: { message: "Auth action not supported" } };
    }
  },

  async handleSignup(request, env, config, encryption) {
    try {
      const contentType = request.headers.get("Content-Type") || "";
      const sessionId = request.headers.get("X-Session-ID");
      let payload;

      Logger.debug("Signup request received", {
        contentType,
        hasEncryption: !!encryption,
        sessionId: sessionId || "None",
      });

      if (contentType.includes("encrypted")) {
        try {
          // Get session-specific encryption key if available
          let sessionEncryption = encryption;
          if (sessionId && env.SAINT_CENTRAL_KV) {
            const sessionData = await env.SAINT_CENTRAL_KV.get(
              `session:${sessionId}`,
              { type: "json" }
            );
            if (sessionData && sessionData.sessionKey) {
              sessionEncryption = new Encryption(sessionData.sessionKey);
              Logger.debug("Using session-specific encryption key");
            }
          }

          const encryptedText = await request.text();
          Logger.debug("Encrypted payload received", {
            payloadLength: encryptedText.length,
            payloadPreview: encryptedText.substring(0, 100) + "...",
          });

          const encryptedData = JSON.parse(encryptedText);
          Logger.debug("Parsed encrypted data", {
            version: encryptedData.version,
            algorithm: encryptedData.algorithm,
            encrypted: encryptedData.encrypted,
            dataLength: encryptedData.data?.length,
          });

          payload = await sessionEncryption.decrypt(encryptedData);
          Logger.debug("Decryption successful", {
            hasEmail: !!payload.email,
            hasPassword: !!payload.password,
          });
        } catch (decryptError) {
          Logger.error("Decryption failed in signup", {
            error: decryptError.message,
            stack: decryptError.stack,
            sessionId,
          });
          return {
            error: {
              message: "Failed to decrypt request payload",
              code: "DECRYPTION_ERROR",
              details:
                process.env.NODE_ENV === "development"
                  ? decryptError.message
                  : undefined,
            },
          };
        }
      } else {
        payload = await request.json();
        Logger.debug("Unencrypted payload received");
      }

      // Validate input
      if (!payload.email || !Validator.email(payload.email)) {
        return { error: { message: "Valid email required" } };
      }

      const passwordValidation = Validator.password(
        payload.password,
        config.security.passwordMinLength
      );
      if (!passwordValidation.valid) {
        return { error: { message: passwordValidation.message } };
      }

      // Call Supabase Auth API
      const response = await fetch(`${config.supabase.url}/auth/v1/signup`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.supabase.serviceKey}`,
          apikey: config.supabase.serviceKey,
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

      if (!response.ok) {
        return { error: result };
      }

      return { data: result };
    } catch (error) {
      Logger.error("Signup failed", {
        error: error.message,
        stack: error.stack,
      });
      return { error: { message: "Signup failed", code: "SIGNUP_ERROR" } };
    }
  },

  async handleSignin(request, env, config, encryption) {
    try {
      const contentType = request.headers.get("Content-Type") || "";
      const sessionId = request.headers.get("X-Session-ID");
      let payload;

      Logger.debug("Signin request received", {
        contentType,
        hasEncryption: !!encryption,
        sessionId: sessionId || "None",
      });

      if (contentType.includes("encrypted")) {
        try {
          // Get session-specific encryption key if available
          let sessionEncryption = encryption;
          if (sessionId && env.SAINT_CENTRAL_KV) {
            const sessionData = await env.SAINT_CENTRAL_KV.get(
              `session:${sessionId}`,
              { type: "json" }
            );
            if (sessionData && sessionData.sessionKey) {
              sessionEncryption = new Encryption(sessionData.sessionKey);
              Logger.debug("Using session-specific encryption key");
            }
          }

          const encryptedText = await request.text();
          Logger.debug("Encrypted payload received", {
            payloadLength: encryptedText.length,
            payloadPreview: encryptedText.substring(0, 100) + "...",
          });

          const encryptedData = JSON.parse(encryptedText);
          Logger.debug("Parsed encrypted data", {
            version: encryptedData.version,
            algorithm: encryptedData.algorithm,
            encrypted: encryptedData.encrypted,
            dataLength: encryptedData.data?.length,
          });

          payload = await sessionEncryption.decrypt(encryptedData);
          Logger.debug("Decryption successful", {
            hasEmail: !!payload.email,
            hasPassword: !!payload.password,
          });
        } catch (decryptError) {
          Logger.error("Decryption failed in signin", {
            error: decryptError.message,
            stack: decryptError.stack,
            sessionId,
          });
          return {
            error: {
              message: "Failed to decrypt request payload",
              code: "DECRYPTION_ERROR",
              details:
                process.env.NODE_ENV === "development"
                  ? decryptError.message
                  : undefined,
            },
          };
        }
      } else {
        payload = await request.json();
        Logger.debug("Unencrypted payload received");
      }

      // Validate input
      if (!payload.email || !Validator.email(payload.email)) {
        return { error: { message: "Valid email required" } };
      }

      if (!payload.password) {
        return { error: { message: "Password required" } };
      }

      // Check for brute force
      const bruteForceCheck = await Security.checkBruteForce(
        payload.email,
        env,
        config
      );
      if (bruteForceCheck.blocked) {
        await Security.logSecurityEvent(
          {
            type: "BRUTE_FORCE_BLOCKED",
            email: payload.email,
            ip: request.headers.get("CF-Connecting-IP"),
            remainingTime: bruteForceCheck.remainingTime,
            sessionId,
          },
          env
        );

        return {
          error: {
            message: "Too many failed attempts. Please try again later.",
            code: "RATE_LIMITED",
          },
        };
      }

      // Call Supabase Auth API
      const response = await fetch(
        `${config.supabase.url}/auth/v1/token?grant_type=password`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${config.supabase.serviceKey}`,
            apikey: config.supabase.serviceKey,
          },
          body: JSON.stringify({
            email: payload.email,
            password: payload.password,
          }),
        }
      );

      const result = await response.json();

      if (!response.ok) {
        await Security.recordFailedLogin(payload.email, env, config);
        await Security.logSecurityEvent(
          {
            type: "LOGIN_FAILED",
            email: payload.email,
            ip: request.headers.get("CF-Connecting-IP"),
            error: result.error_description,
            sessionId,
          },
          env
        );

        return { error: result };
      }

      // Clear failed login attempts on success
      await Security.clearFailedLogins(payload.email, env);

      await Security.logSecurityEvent(
        {
          type: "LOGIN_SUCCESS",
          email: payload.email,
          ip: request.headers.get("CF-Connecting-IP"),
          sessionId,
        },
        env
      );

      return { data: result };
    } catch (error) {
      Logger.error("Signin failed", {
        error: error.message,
        stack: error.stack,
      });
      return { error: { message: "Signin failed", code: "SIGNIN_ERROR" } };
    }
  },

  async handleSignout(request, env, config) {
    try {
      const authHeader = request.headers.get("Authorization");
      const token = authHeader ? authHeader.replace("Bearer ", "") : null;

      if (!token) {
        return { error: { message: "No token provided" } };
      }

      const response = await fetch(`${config.supabase.url}/auth/v1/logout`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          apikey: config.supabase.serviceKey,
        },
      });

      if (!response.ok) {
        const result = await response.json();
        return { error: result };
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

      if (!token) {
        return { error: { message: "No session found" } };
      }

      const jwt = new JWT(config.security.jwtSecret);
      const payload = await jwt.verify(token);

      if (!payload) {
        return { error: { message: "Invalid session" } };
      }

      const response = await fetch(`${config.supabase.url}/auth/v1/user`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          apikey: config.supabase.serviceKey,
        },
      });

      const result = await response.json();

      if (!response.ok) {
        return { error: result };
      }

      // Add security metadata
      result.security = {
        lastVerified: Date.now(),
        clientIP: request.headers.get("CF-Connecting-IP"),
        userAgent: request.headers.get("User-Agent"),
        sessionId: crypto.randomUUID(),
      };

      return { data: result };
    } catch (error) {
      Logger.error("Session validation failed", { error: error.message });
      return { error: { message: "Session validation failed" } };
    }
  },

  async handlePasswordRecovery(request, env, config) {
    try {
      const { email } = await request.json();

      if (!email || !Validator.email(email)) {
        return { error: { message: "Valid email required" } };
      }

      const response = await fetch(`${config.supabase.url}/auth/v1/recover`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.supabase.serviceKey}`,
          apikey: config.supabase.serviceKey,
        },
        body: JSON.stringify({ email }),
      });

      const result = await response.json();

      await Security.logSecurityEvent(
        {
          type: "PASSWORD_RECOVERY_REQUEST",
          email,
          success: response.ok,
          ip: request.headers.get("CF-Connecting-IP"),
        },
        env
      );

      if (!response.ok) {
        return { error: result };
      }

      return { data: result };
    } catch (error) {
      Logger.error("Password recovery failed", { error: error.message });
      return { error: { message: "Password recovery failed" } };
    }
  },

  async handleTokenRefresh(request, env, config) {
    try {
      const { refresh_token } = await request.json();

      if (!refresh_token) {
        return { error: { message: "Refresh token required" } };
      }

      const response = await fetch(
        `${config.supabase.url}/auth/v1/token?grant_type=refresh_token`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${config.supabase.serviceKey}`,
            apikey: config.supabase.serviceKey,
          },
          body: JSON.stringify({ refresh_token }),
        }
      );

      const result = await response.json();

      await Security.logSecurityEvent(
        {
          type: "TOKEN_REFRESH",
          success: response.ok,
          ip: request.headers.get("CF-Connecting-IP"),
        },
        env
      );

      if (!response.ok) {
        return { error: result };
      }

      return { data: result };
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

      // Generate a unique session-specific encryption key
      const sessionKey = Config.generateEncryptionKey();

      // Create a secure session identifier
      const sessionId = crypto.randomUUID();

      // Store the session key temporarily (expires in 1 hour)
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
          { expirationTtl: 3600 } // 1 hour
        );
      }

      // Log the key exchange for security monitoring
      await Security.logSecurityEvent(
        {
          type: "KEY_EXCHANGE",
          sessionId,
          clientIP,
          userAgent,
          requestId,
        },
        env
      );

      Logger.info("Key exchange completed", {
        sessionId,
        clientIP,
        requestId,
      });

      return {
        data: {
          sessionId,
          sessionKey,
          algorithm: "AES-256-GCM",
          version: 2,
          expiresAt: Date.now() + 3600000, // 1 hour
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

  // Handle storage operations
  async handleStorage(request, env, config, pathParts) {
    const storageAction = pathParts[1];

    try {
      switch (storageAction) {
        case "bucket":
          return await this.handleBucketOperations(
            request,
            env,
            config,
            pathParts
          );
        case "object":
          return await this.handleObjectOperations(
            request,
            env,
            config,
            pathParts
          );
        default:
          return { error: { message: "Storage action not supported" } };
      }
    } catch (error) {
      Logger.error("Storage operation failed", { error: error.message });
      return { error: { message: "Storage operation failed" } };
    }
  },

  async handleBucketOperations(request, env, config, pathParts) {
    const baseUrl = `${config.supabase.url}/storage/v1/bucket`;
    const headers = {
      Authorization: `Bearer ${config.supabase.serviceKey}`,
      apikey: config.supabase.serviceKey,
    };

    if (pathParts.length === 2) {
      if (request.method === "GET") {
        const response = await fetch(baseUrl, { method: "GET", headers });
        const result = await response.json();
        return response.ok ? { data: result } : { error: result };
      } else if (request.method === "POST") {
        const { id, public: isPublic } = await request.json();
        const response = await fetch(baseUrl, {
          method: "POST",
          headers: { ...headers, "Content-Type": "application/json" },
          body: JSON.stringify({ id, public: isPublic }),
        });
        const result = await response.json();
        return response.ok ? { data: result } : { error: result };
      }
    } else if (pathParts.length === 3) {
      const bucketName = pathParts[2];
      if (request.method === "DELETE") {
        const response = await fetch(`${baseUrl}/${bucketName}`, {
          method: "DELETE",
          headers,
        });
        const result = await response.json();
        return response.ok ? { data: result } : { error: result };
      }
    }

    return { error: { message: "Bucket operation not supported" } };
  },

  async handleObjectOperations(request, env, config, pathParts) {
    if (pathParts[2] === "list" && pathParts.length > 3) {
      return await this.handleListObjects(request, env, config, pathParts);
    } else if (pathParts.length > 3) {
      return await this.handleFileOperations(request, env, config, pathParts);
    }

    return { error: { message: "Object operation not supported" } };
  },

  async handleListObjects(request, env, config, pathParts) {
    const bucketName = pathParts[3];
    const url = new URL(request.url);
    const prefix = url.searchParams.get("prefix") || "";
    const limit = url.searchParams.get("limit") || "100";
    const offset = url.searchParams.get("offset") || "0";

    const response = await fetch(
      `${config.supabase.url}/storage/v1/object/list/${bucketName}?prefix=${prefix}&limit=${limit}&offset=${offset}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${config.supabase.serviceKey}`,
          apikey: config.supabase.serviceKey,
        },
      }
    );

    const result = await response.json();
    return response.ok ? { data: result } : { error: result };
  },

  async handleFileOperations(request, env, config, pathParts) {
    const bucketName = pathParts[2];
    const filePath = pathParts.slice(3).join("/");
    const baseUrl = `${config.supabase.url}/storage/v1/object/${bucketName}/${filePath}`;

    const headers = {
      Authorization: `Bearer ${config.supabase.serviceKey}`,
      apikey: config.supabase.serviceKey,
    };

    switch (request.method) {
      case "GET": {
        const response = await fetch(baseUrl, { method: "GET", headers });
        if (!response.ok) {
          const result = await response.json();
          return { error: result };
        }
        const arrayBuffer = await response.arrayBuffer();
        return { data: arrayBuffer };
      }

      case "POST": {
        const formData = await request.formData();
        const file = formData.get("file");

        if (!file) {
          return { error: { message: "No file provided" } };
        }

        const arrayBuffer = await file.arrayBuffer();

        // Enhanced malware scanning
        const scanResult = await scanFileForMalware(arrayBuffer, file.name);
        if (!scanResult.safe) {
          await Security.logSecurityEvent(
            {
              type: "MALWARE_DETECTED",
              bucket: bucketName,
              path: filePath,
              threats: scanResult.threats,
              contentType: file.type,
              size: arrayBuffer.byteLength,
              ip: request.headers.get("CF-Connecting-IP"),
            },
            env
          );

          return {
            error: {
              message: "File rejected for security reasons",
              threats: scanResult.threats,
            },
          };
        }

        const uploadFormData = new FormData();
        uploadFormData.append(
          "file",
          new Blob([arrayBuffer], { type: file.type })
        );

        const response = await fetch(baseUrl, {
          method: "POST",
          headers,
          body: uploadFormData,
        });

        const result = await response.json();
        return response.ok ? { data: result } : { error: result };
      }

      case "DELETE": {
        const response = await fetch(baseUrl, { method: "DELETE", headers });
        const result = await response.json();
        return response.ok ? { data: result } : { error: result };
      }

      default:
        return { error: { message: "File operation not supported" } };
    }
  },

  // Handle functions and RPC
  async handleFunctions(request, env, config, pathParts) {
    if (
      pathParts[0] === "functions" &&
      pathParts[1] === "v1" &&
      pathParts.length > 2
    ) {
      return await this.handleEdgeFunction(request, env, config, pathParts);
    } else if (
      pathParts[0] === "rest" &&
      pathParts[2] === "rpc" &&
      pathParts.length > 3
    ) {
      return await this.handleRPCFunction(request, env, config, pathParts);
    }

    return { error: { message: "Function not supported" } };
  },

  async handleEdgeFunction(request, env, config, pathParts) {
    const functionName = pathParts[2];
    const payload = await request.json();
    const requestId = Security.generateRequestId();

    Logger.info("Edge Function Invocation", { functionName, requestId });

    try {
      const response = await fetch(
        `${config.supabase.url}/functions/v1/${functionName}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${config.supabase.serviceKey}`,
            apikey: config.supabase.serviceKey,
          },
          body: JSON.stringify(payload),
        }
      );

      const result = await response.json();
      return response.ok ? { data: result } : { error: result };
    } catch (error) {
      Logger.error("Edge Function Error", {
        functionName,
        requestId,
        error: error.message,
      });
      return { error: { message: "Function invocation failed" } };
    }
  },

  async handleRPCFunction(request, env, config, pathParts) {
    const functionName = pathParts[3];
    const payload = await request.json();
    const db = this.getDatabase(config);

    try {
      // Validate function name
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(functionName)) {
        return { error: { message: "Invalid function name" } };
      }

      const paramNames = Object.keys(payload);
      const paramValues = Object.values(payload);
      const paramPlaceholders = paramValues
        .map((_, i) => `$${i + 1}`)
        .join(", ");

      const sql = `SELECT * FROM ${functionName}(${paramPlaceholders})`;
      const result = await db.query(sql, paramValues);

      return result.error ? { error: result.error } : { data: result.rows };
    } catch (error) {
      Logger.error("RPC Function Error", {
        functionName,
        error: error.message,
      });
      return { error: { message: "RPC function call failed" } };
    }
  },
};

// Main worker
export default {
  async fetch(request, env, ctx) {
    const startTime = Date.now();
    let config;

    try {
      // Initialize configuration
      config = new Config(env);
      Logger.setLevel(config.monitoring.logLevel);

      // Generate request ID for tracing
      const requestId = Security.generateRequestId();

      // Basic CORS and security headers
      const corsHeaders = {
        "Access-Control-Allow-Origin": config.cors.allowedOrigins.includes("*")
          ? "*"
          : config.cors.allowedOrigins.join(", "),
        "Access-Control-Allow-Methods": config.cors.allowedMethods.join(", "),
        "Access-Control-Allow-Headers": config.cors.allowedHeaders.join(", "),
        "X-Request-ID": requestId,
        "X-Saint-Central-Version": "2.0.0",
        ...Security.generateSecureHeaders(),
      };

      // Handle OPTIONS requests
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders });
      }

      // Security checks
      const securityCheck = Security.checkSecurityHeaders(request);
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

      // Rate limiting
      const rateLimitResult = await Security.rateLimit(request, env, config);
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
          { status: 429, headers: rateLimitHeaders }
        );
      }

      // Parse request
      const url = new URL(request.url);
      const pathParts = url.pathname.split("/").filter(Boolean);

      Logger.info("Request Received", {
        requestId,
        method: request.method,
        path: url.pathname,
        ip: request.headers.get("CF-Connecting-IP"),
        userAgent: request.headers.get("User-Agent"),
      });

      // Health check
      if (pathParts.length === 0) {
        const db = Handlers.getDatabase(config);
        const stats = db.getStats();

        return new Response(
          JSON.stringify({
            name: "Saint Central API",
            version: "2.0.0",
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

      // Route requests
      let result;

      if (pathParts[0] === "rest" && pathParts[1] === "v1") {
        result = await Handlers.handleDatabase(request, env, config, pathParts);
      } else if (pathParts[0] === "auth") {
        result = await Handlers.handleAuth(request, env, config, pathParts);
      } else if (pathParts[0] === "storage") {
        result = await Handlers.handleStorage(request, env, config, pathParts);
      } else if (
        pathParts[0] === "functions" ||
        (pathParts[0] === "rest" && pathParts[2] === "rpc")
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
        };
      }

      // Log response
      const duration = Date.now() - startTime;
      Logger.info("Request Completed", {
        requestId,
        duration,
        success: !result.error,
        statusCode: result.error ? 400 : 200,
      });

      // Add rate limit headers to successful responses
      const responseHeaders = {
        ...corsHeaders,
        "Content-Type": "application/json",
        "Cache-Control": "private, no-cache, no-store, must-revalidate",
        "X-Response-Time": `${duration}ms`,
      };

      if (rateLimitResult.limit) {
        responseHeaders["X-RateLimit-Limit"] = rateLimitResult.limit.toString();
        responseHeaders["X-RateLimit-Remaining"] =
          rateLimitResult.remaining?.toString() || "0";
        responseHeaders["X-RateLimit-Reset"] = new Date(
          rateLimitResult.resetAt || Date.now() + 60000
        ).toISOString();
      }

      // Return response
      if (result.error) {
        const safeError = {
          message: result.error.message,
          code: result.error.code || "ERROR",
          requestId,
        };

        return new Response(JSON.stringify({ error: safeError }), {
          status: 400,
          headers: responseHeaders,
        });
      } else {
        return new Response(JSON.stringify({ data: result.data, requestId }), {
          status: 200,
          headers: responseHeaders,
        });
      }
    } catch (error) {
      const requestId = Security.generateRequestId();
      const duration = Date.now() - startTime;

      Logger.error("Unhandled Error", {
        requestId,
        error: error.message,
        stack: error.stack,
        duration,
      });

      if (config) {
        await Security.logSecurityEvent(
          {
            type: "SERVER_ERROR",
            error: error.message,
            requestId,
          },
          env
        );
      }

      return new Response(
        JSON.stringify({
          error: {
            message: "An unexpected error occurred",
            code: "SERVER_ERROR",
            requestId,
          },
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            "X-Request-ID": requestId,
            ...Security.generateSecureHeaders(),
          },
        }
      );
    }
  },
};
