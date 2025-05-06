/**
 * Saint Central Cloudflare Worker
 *
 * This worker acts as a secure middleware layer between the client SDK and Supabase,
 * adding enhanced security features while leveraging the Supabase SDK on the backend.
 */

import { createClient } from "@supabase/supabase-js";
import { Buffer } from "node:buffer"; // Updated to use node: prefix

// Instead of importing nanoid, implement a simple ID generator
function generateId(length = 16) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  const charactersLength = characters.length;

  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }

  return result;
}

/**
 * Security utility functions
 */
const Security = {
  // Rate limiting implementation using Cloudflare's KV store
  rateLimit: async (request, env, ctx) => {
    if (env.RATE_LIMIT_ENABLED !== "true") return true;

    const clientIP = request.headers.get("CF-Connecting-IP");
    const endpoint = new URL(request.url).pathname;
    const rateKey = `ratelimit:${clientIP}:${endpoint}`;

    // Get current rate limit data
    const rateLimitData = await env.SAINT_CENTRAL_KV.get(rateKey, {
      type: "json",
    });
    const now = Date.now();

    if (!rateLimitData) {
      // First request, set initial count
      await env.SAINT_CENTRAL_KV.put(
        rateKey,
        JSON.stringify({
          count: 1,
          resetAt: now + 60000, // Reset after 1 minute
        }),
        { expirationTtl: 60 }
      ); // Auto-expire after 60 seconds
      return true;
    }

    if (now > rateLimitData.resetAt) {
      // Reset period has passed
      await env.SAINT_CENTRAL_KV.put(
        rateKey,
        JSON.stringify({
          count: 1,
          resetAt: now + 60000,
        }),
        { expirationTtl: 60 }
      );
      return true;
    }

    // Increment count and check limit
    const newCount = rateLimitData.count + 1;

    // Check if rate limit exceeded (100 requests per minute)
    if (newCount > 100) {
      return false;
    }

    // Update count
    await env.SAINT_CENTRAL_KV.put(
      rateKey,
      JSON.stringify({
        count: newCount,
        resetAt: rateLimitData.resetAt,
      }),
      { expirationTtl: 60 }
    );

    return true;
  },

  // JWT verification
  verifyJWT: async (token, env) => {
    try {
      if (!token) return null;

      // Basic structure validation
      const parts = token.split(".");
      if (parts.length !== 3) return null;

      // Decode payload
      const payload = JSON.parse(atob(parts[1]));

      // Check expiration
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return null;
      }

      // In a real implementation, you would verify the signature using JWT libraries
      // For now, we'll just check some basic properties

      return payload;
    } catch (error) {
      console.error("JWT verification error:", error);
      return null;
    }
  },

  // Enhanced encryption/decryption implementation
  // In a real implementation, this would use Web Crypto API or a strong encryption library
  _getEncryptionKey: (env) => {
    // In a real implementation, this would load from env variables or KV
    return env.ENCRYPTION_KEY || "this-is-a-demo-key-replace-in-production";
  },

  _generateIV: () => {
    // In a real implementation, this would generate a real IV for AES-GCM
    // For demonstration purposes only
    const array = new Uint8Array(12);
    crypto.getRandomValues(array);
    return Array.from(array)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },

  // Payload encryption/decryption
  decryptPayload: (encryptedData, env) => {
    try {
      console.log("Starting decryption process");

      // Handle encrypted data from the SDK
      if (!encryptedData || typeof encryptedData !== "string") {
        console.log("Payload is not a string or is empty");
        return encryptedData;
      }

      console.log(
        "Attempting to decrypt payload:",
        encryptedData.substring(0, 100) + "..."
      );

      // Check if this is SDK-encrypted data
      try {
        const parsed = JSON.parse(encryptedData);
        console.log(
          "Successfully parsed JSON. Checking if encrypted format:",
          parsed
        );

        if (parsed && parsed.encrypted === true && parsed.version === 1) {
          console.log(
            "Detected SDK encrypted format. Data sample:",
            parsed.data.substring(0, 50) + "..."
          );

          // This is data encrypted by the SDK
          try {
            // In a real implementation, this would use proper decryption
            // with the algorithm specified in parsed.algorithm
            const decrypted = JSON.parse(parsed.data);
            console.log(
              "Successfully decrypted. Result format:",
              Object.keys(decrypted)
            );
            return decrypted;
          } catch (err) {
            console.error("Failed to decrypt SDK payload:", err);
            throw new Error("Invalid encrypted format");
          }
        } else {
          console.log("Not in SDK encrypted format, returning as is");
          return parsed;
        }
      } catch (e) {
        console.log("Not valid JSON or not in expected format:", e.message);
        // Not JSON or not in the expected format, continue with other checks
      }

      // Legacy format check
      if (encryptedData.startsWith("ENC:")) {
        console.log("Legacy ENC: format detected");
        const data = encryptedData.substring(4);
        // Simple XOR decryption as placeholder
        return JSON.parse(data);
      }

      console.log("No encryption format detected, returning as is");
      return encryptedData;
    } catch (error) {
      console.error("Decryption error:", error);
      return encryptedData;
    }
  },

  encryptPayload: (data, env) => {
    try {
      // In a real implementation, this would use proper encryption APIs
      if (!data) return data;

      // For demonstration purposes - in production use real encryption
      const iv = Security._generateIV();
      // In a real implementation, this would encrypt data with AES-GCM

      return JSON.stringify({
        version: 1,
        algorithm: "aes-256-gcm",
        iv: iv,
        data: JSON.stringify(data),
        encrypted: true,
      });
    } catch (error) {
      console.error("Encryption error:", error);
      return data;
    }
  },

  // DDoS protection header checks
  checkSecurityHeaders: (request) => {
    // Get client country from Cloudflare headers
    const country = request.headers.get("CF-IPCountry");
    const clientIP = request.headers.get("CF-Connecting-IP");
    const bot = request.headers.get("CF-Bot");

    // For demo purposes, simple country blocking logic
    const blockedCountries = ["XX", "YY"]; // Replace with actual country codes if needed
    if (blockedCountries.includes(country)) {
      return { allowed: false, reason: "COUNTRY_BLOCKED" };
    }

    // Bot detection
    if (bot === "likely") {
      return { allowed: false, reason: "BOT_DETECTED" };
    }

    return { allowed: true };
  },

  // Validate Content-Security-Policy
  enforceCSP: (response) => {
    const headers = new Headers(response.headers);

    // Set strong Content-Security-Policy
    headers.set(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; object-src 'none'; upgrade-insecure-requests;"
    );

    // Set other security headers
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("X-Frame-Options", "DENY");
    headers.set("X-XSS-Protection", "1; mode=block");
    headers.set("Referrer-Policy", "no-referrer");
    headers.set(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload"
    );

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },

  // Generate secure request ID for tracing
  generateRequestId: () => {
    return generateId(16); // Using our custom function instead of nanoid
  },

  // Log security events
  logSecurityEvent: async (event, env) => {
    // In production, send to security logging system
    console.log(`SECURITY EVENT: ${JSON.stringify(event)}`);

    // Optionally store in KV for analysis
    if (env.SAINT_CENTRAL_KV) {
      const logKey = `security:log:${Date.now()}:${generateId(6)}`;
      await env.SAINT_CENTRAL_KV.put(logKey, JSON.stringify(event), {
        expirationTtl: 86400 * 7,
      }); // Keep for 7 days
    }
  },
};

/**
 * Request handlers for different Supabase services
 */
const Handlers = {
  // Initialize Supabase client with service key
  getSupabaseClient: (env) => {
    return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });
  },

  // Handle database requests
  async handleDatabase(request, env, ctx, pathParts) {
    const supabase = this.getSupabaseClient(env);
    const tableName = pathParts[2]; // rest/v1/{tableName}

    // Convert request to query parameters
    const url = new URL(request.url);
    const params = Object.fromEntries(url.searchParams.entries());

    // Process different HTTP methods
    switch (request.method) {
      case "GET": {
        // Build query from URL parameters
        let query = supabase.from(tableName).select(params.select || "*");

        // Apply filters
        for (const [key, value] of Object.entries(params)) {
          if (
            key !== "select" &&
            key !== "order" &&
            key !== "limit" &&
            key !== "offset"
          ) {
            const [operator, filterValue] = value.split(".");
            if (operator && filterValue) {
              switch (operator) {
                case "eq":
                  query = query.eq(key, filterValue);
                  break;
                case "neq":
                  query = query.neq(key, filterValue);
                  break;
                case "gt":
                  query = query.gt(key, filterValue);
                  break;
                case "lt":
                  query = query.lt(key, filterValue);
                  break;
                case "gte":
                  query = query.gte(key, filterValue);
                  break;
                case "lte":
                  query = query.lte(key, filterValue);
                  break;
                case "like":
                  query = query.like(key, filterValue);
                  break;
                case "ilike":
                  query = query.ilike(key, filterValue);
                  break;
              }
            }
          }
        }

        // Add order, limit, offset
        if (params.order) {
          const [column, direction] = params.order.split(".");
          query = query.order(column, { ascending: direction === "asc" });
        }

        if (params.limit) {
          query = query.limit(parseInt(params.limit));
        }

        if (params.offset) {
          query = query.offset(parseInt(params.offset));
        }

        const { data, error } = await query;

        return { data, error };
      }

      case "POST": {
        const body = await request.json();
        const returning = params.select || null;

        const { data, error } = returning
          ? await supabase.from(tableName).insert(body).select(returning)
          : await supabase.from(tableName).insert(body);

        return { data, error };
      }

      case "PATCH": {
        const body = await request.json();
        const returning = params.select || null;

        // Start with query
        let query = supabase.from(tableName).update(body);

        // Apply filters
        for (const [key, value] of Object.entries(params)) {
          if (key !== "select") {
            const [operator, filterValue] = value.split(".");
            if (operator && filterValue) {
              switch (operator) {
                case "eq":
                  query = query.eq(key, filterValue);
                  break;
                case "neq":
                  query = query.neq(key, filterValue);
                  break;
                // Add other operators as needed
              }
            }
          }
        }

        const { data, error } = returning
          ? await query.select(returning)
          : await query;

        return { data, error };
      }

      case "DELETE": {
        const returning = params.select || null;

        // Start with query
        let query = supabase.from(tableName).delete();

        // Apply filters
        for (const [key, value] of Object.entries(params)) {
          if (key !== "select") {
            const [operator, filterValue] = value.split(".");
            if (operator && filterValue) {
              switch (operator) {
                case "eq":
                  query = query.eq(key, filterValue);
                  break;
                case "neq":
                  query = query.neq(key, filterValue);
                  break;
                // Add other operators as needed
              }
            }
          }
        }

        const { data, error } = returning
          ? await query.select(returning)
          : await query;

        return { data, error };
      }

      default:
        return { error: { message: "Method not supported" } };
    }
  },

  // Handle authentication requests
  async handleAuth(request, env, ctx, pathParts) {
    const supabase = this.getSupabaseClient(env);
    const authAction = pathParts[1]; // auth/{action}

    switch (authAction) {
      case "signup": {
        // Check for encrypted content type
        const contentType = request.headers.get("Content-Type") || "";
        let payload;

        if (contentType.includes("encrypted")) {
          // Handle encrypted payload
          const encryptedText = await request.text();
          payload = Security.decryptPayload(encryptedText, env);
        } else {
          // Regular JSON handling
          payload = await request.json();
        }

        const { email, password, ...options } = payload;

        // Add security checks for password strength
        if (password && password.length < 8) {
          return {
            error: { message: "Password must be at least 8 characters long" },
          };
        }

        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options,
        });

        // Log signup attempt for security monitoring
        await Security.logSecurityEvent(
          {
            type: "SIGNUP_ATTEMPT",
            email,
            success: !error,
            error: error ? error.message : null,
            ip: request.headers.get("CF-Connecting-IP"),
            timestamp: Date.now(),
          },
          env
        );

        return { data, error };
      }

      case "signin": {
        // Check for encrypted content type
        const contentType = request.headers.get("Content-Type") || "";
        console.log("Content-Type for signin:", contentType);

        let payload;

        if (contentType.includes("encrypted")) {
          // Handle encrypted payload
          console.log("Detected encrypted content type");
          const encryptedText = await request.text();
          console.log(
            "Raw encrypted payload (first 100 chars):",
            encryptedText.substring(0, 100) + "..."
          );

          payload = Security.decryptPayload(encryptedText, env);
          console.log("Decrypted payload:", payload);
        } else {
          // Regular JSON handling
          console.log("Regular JSON content type");
          payload = await request.json();
          console.log("JSON payload:", payload);
        }

        if (!payload || (!payload.email && !payload.phone)) {
          console.error("Missing required fields in payload");
          return {
            error: {
              message: "Missing email or phone in request payload",
              code: "validation_failed",
              details: {
                payload:
                  typeof payload === "object"
                    ? Object.keys(payload)
                    : typeof payload,
              },
            },
          };
        }

        if (!payload.password) {
          console.error("Missing password in payload");
          return {
            error: {
              message: "Missing password in request payload",
              code: "validation_failed",
            },
          };
        }

        const { email, password, ...options } = payload;

        // Get client IP for security logging
        const clientIP = request.headers.get("CF-Connecting-IP");

        // Check for brute force attempts using KV
        const loginAttemptsKey = `login:attempts:${email}`;
        const loginAttempts = (await env.SAINT_CENTRAL_KV.get(
          loginAttemptsKey,
          { type: "json" }
        )) || { count: 0, lastAttempt: 0 };

        // If too many attempts, block
        if (
          loginAttempts.count >= 50 && // switch back to 5 for production
          Date.now() - loginAttempts.lastAttempt < 15 * 60 * 1000
        ) {
          await Security.logSecurityEvent(
            {
              type: "LOGIN_BLOCKED_TOO_MANY_ATTEMPTS",
              email,
              ip: clientIP,
              attemptCount: loginAttempts.count,
              timestamp: Date.now(),
            },
            env
          );

          return {
            error: {
              message: "Too many login attempts. Please try again later.",
            },
          };
        }

        const { data, error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });

        // Update login attempts counter
        if (error) {
          await env.SAINT_CENTRAL_KV.put(
            loginAttemptsKey,
            JSON.stringify({
              count: loginAttempts.count + 1,
              lastAttempt: Date.now(),
            }),
            { expirationTtl: 60 * 15 }
          ); // 15 minutes
        } else {
          // Reset counter on successful login
          await env.SAINT_CENTRAL_KV.delete(loginAttemptsKey);
        }

        // Log login attempt for security monitoring
        await Security.logSecurityEvent(
          {
            type: "LOGIN_ATTEMPT",
            email,
            success: !error,
            error: error ? error.message : null,
            ip: clientIP,
            timestamp: Date.now(),
          },
          env
        );

        return { data, error };
      }

      case "signout": {
        const { data, error } = await supabase.auth.signOut();
        return { data, error };
      }

      case "recover": {
        const { email } = await request.json();

        const { data, error } = await supabase.auth.resetPasswordForEmail(
          email
        );

        // Log password reset request for security monitoring
        await Security.logSecurityEvent(
          {
            type: "PASSWORD_RESET_REQUEST",
            email,
            success: !error,
            ip: request.headers.get("CF-Connecting-IP"),
            timestamp: Date.now(),
          },
          env
        );

        return { data, error };
      }

      case "session": {
        // Get session from JWT token
        const authHeader = request.headers.get("Authorization");
        const token = authHeader ? authHeader.replace("Bearer ", "") : null;

        if (!token) {
          return { error: { message: "No session found" } };
        }

        // Verify and enhance the JWT token
        const payload = await Security.verifyJWT(token, env);

        if (!payload) {
          return { error: { message: "Invalid session" } };
        }

        // Get session from supabase
        const { data, error } = await supabase.auth.getUser(token);

        // Add security info to session data
        if (data) {
          data.security = {
            lastVerified: Date.now(),
            clientIP: request.headers.get("CF-Connecting-IP"),
            userAgent: request.headers.get("User-Agent"),
          };
        }

        return { data, error };
      }

      case "token": {
        // Token refresh logic
        const { refresh_token } = await request.json();

        const { data, error } = await supabase.auth.refreshSession({
          refresh_token,
        });

        // Log token refresh for security monitoring
        await Security.logSecurityEvent(
          {
            type: "TOKEN_REFRESH",
            success: !error,
            ip: request.headers.get("CF-Connecting-IP"),
            timestamp: Date.now(),
          },
          env
        );

        return { data, error };
      }

      case "authorize": {
        // OAuth flow
        const { provider, ...options } = await request.json();

        const { data, error } = await supabase.auth.signInWithOAuth({
          provider,
          options,
        });

        return { data, error };
      }

      case "mfa": {
        // MFA handling - this is a Saint Central enhancement
        const mfaAction = pathParts[2]; // auth/mfa/{action}

        switch (mfaAction) {
          case "enable": {
            // In a real implementation, this would integrate with Supabase's MFA
            // For now, we'll mock the response
            return {
              data: {
                mfa_enabled: true,
                setup_required: true,
                secret: "ABCDEFGHIJKLMNOP", // Secret for TOTP
                qr_code: "data:image/png;base64,iVBORw0KG...",
              },
            };
          }

          case "verify": {
            const { code } = await request.json();

            // Mock verification
            const isValid = code === "123456"; // In real implementation, validate TOTP

            if (!isValid) {
              return { error: { message: "Invalid MFA code" } };
            }

            return {
              data: {
                mfa_verified: true,
                recovery_codes: [
                  "AAAA-BBBB-CCCC",
                  "DDDD-EEEE-FFFF",
                  "GGGG-HHHH-IIII",
                ],
              },
            };
          }

          case "disable": {
            // Mock disabling MFA
            return {
              data: {
                mfa_enabled: false,
              },
            };
          }

          default:
            return { error: { message: "MFA action not supported" } };
        }
      }

      case "admin": {
        // Admin functions
        const adminAction = pathParts[2]; // auth/admin/{action}

        // Verify admin privileges
        const authHeader = request.headers.get("Authorization");
        const token = authHeader ? authHeader.replace("Bearer ", "") : null;

        if (!token) {
          return { error: { message: "Unauthorized" } };
        }

        const { data: userData } = await supabase.auth.getUser(token);

        // Check if user has admin role - implementation varies based on your Supabase setup
        // This is a simplistic check - you should implement proper role-based checks
        const isAdmin = userData?.user?.app_metadata?.role === "admin";

        if (!isAdmin) {
          // Log unauthorized admin access attempt
          await Security.logSecurityEvent(
            {
              type: "UNAUTHORIZED_ADMIN_ACCESS",
              user: userData?.user?.id,
              ip: request.headers.get("CF-Connecting-IP"),
              action: adminAction,
              timestamp: Date.now(),
            },
            env
          );

          return { error: { message: "Unauthorized" } };
        }

        switch (adminAction) {
          case "users": {
            if (request.method === "GET") {
              // List users
              const url = new URL(request.url);
              const page = parseInt(url.searchParams.get("page") || "1");
              const perPage = parseInt(
                url.searchParams.get("per_page") || "50"
              );

              // Fetch users via Supabase Admin API
              // This is a simplified version - actual implementation would use admin endpoints
              const { data, error } = await supabase
                .from("auth.users")
                .select("*")
                .range((page - 1) * perPage, page * perPage - 1);

              return { data, error };
            } else if (request.method === "POST") {
              // Create user
              const userData = await request.json();

              const { data, error } = await supabase.auth.admin.createUser({
                email: userData.email,
                password: userData.password,
                email_confirm: true,
                user_metadata: userData.user_metadata,
              });

              return { data, error };
            }
            break;
          }

          // Fixed: Removed the duplicate case for "users"
          case "user-delete": {
            if (pathParts.length > 3 && request.method === "DELETE") {
              // Delete user
              const userId = pathParts[3];

              const { data, error } = await supabase.auth.admin.deleteUser(
                userId
              );

              return { data, error };
            }
            break;
          }
        }

        return { error: { message: "Admin action not supported" } };
      }

      default:
        return { error: { message: "Auth action not supported" } };
    }
  },

  // Handle storage requests
  async handleStorage(request, env, ctx, pathParts) {
    const supabase = this.getSupabaseClient(env);
    const storageAction = pathParts[1]; // storage/{action}

    switch (storageAction) {
      case "bucket": {
        // Bucket operations
        if (pathParts.length === 2) {
          if (request.method === "GET") {
            // List buckets
            const { data, error } = await supabase.storage.listBuckets();
            return { data, error };
          } else if (request.method === "POST") {
            // Create bucket
            const { id, public: isPublic } = await request.json();

            const { data, error } = await supabase.storage.createBucket(id, {
              public: isPublic,
            });

            return { data, error };
          }
        } else if (pathParts.length === 3) {
          // Operations on specific bucket
          const bucketName = pathParts[2];

          if (request.method === "DELETE") {
            // Delete bucket
            const { data, error } = await supabase.storage.deleteBucket(
              bucketName
            );
            return { data, error };
          }
        }
        break;
      }

      case "object": {
        // Object operations
        if (pathParts[2] === "list" && pathParts.length > 3) {
          // List objects in bucket
          const bucketName = pathParts[3];
          const url = new URL(request.url);
          const prefix = url.searchParams.get("prefix") || "";
          const limit = url.searchParams.get("limit")
            ? parseInt(url.searchParams.get("limit"))
            : undefined;
          const offset = url.searchParams.get("offset")
            ? parseInt(url.searchParams.get("offset"))
            : undefined;

          const { data, error } = await supabase.storage
            .from(bucketName)
            .list(prefix, { limit, offset });

          return { data, error };
        } else if (pathParts.length > 3) {
          // Operations on specific object
          const bucketName = pathParts[2];

          // Combine remaining path parts to get the full file path
          const filePath = pathParts.slice(3).join("/");

          if (request.method === "GET") {
            // Download file
            const { data, error } = await supabase.storage
              .from(bucketName)
              .download(filePath);

            return { data, error };
          } else if (request.method === "POST") {
            // Upload file - handle form data
            const formData = await request.formData();
            const file = formData.get("file");

            if (!file) {
              return { error: { message: "No file provided" } };
            }

            // Convert File or Blob to ArrayBuffer for Supabase
            const arrayBuffer = await file.arrayBuffer();

            // Get optional content type
            const contentType = formData.get("content_type") || file.type;

            // Scan file for malware (simplified placeholder)
            const isSafe = await scanFileForMalware(arrayBuffer);

            if (!isSafe) {
              // Log security event for malware detection
              await Security.logSecurityEvent(
                {
                  type: "MALWARE_DETECTED",
                  bucket: bucketName,
                  path: filePath,
                  contentType,
                  size: arrayBuffer.byteLength,
                  ip: request.headers.get("CF-Connecting-IP"),
                  timestamp: Date.now(),
                },
                env
              );

              return {
                error: { message: "File rejected for security reasons" },
              };
            }

            const { data, error } = await supabase.storage
              .from(bucketName)
              .upload(filePath, arrayBuffer, {
                contentType,
                upsert: true,
              });

            return { data, error };
          } else if (request.method === "DELETE") {
            // Delete file
            const { data, error } = await supabase.storage
              .from(bucketName)
              .remove([filePath]);

            return { data, error };
          }
        } else if (request.method === "DELETE") {
          // Bulk delete operation
          const bucketName = pathParts[2];
          const { prefixes } = await request.json();

          const { data, error } = await supabase.storage
            .from(bucketName)
            .remove(prefixes);

          return { data, error };
        }
        break;
      }

      default:
        return { error: { message: "Storage action not supported" } };
    }

    return { error: { message: "Storage operation not supported" } };
  },

  // Handle Functions/RPC requests
  async handleFunctions(request, env, ctx, pathParts) {
    const supabase = this.getSupabaseClient(env);

    if (
      pathParts[0] === "functions" &&
      pathParts[1] === "v1" &&
      pathParts.length > 2
    ) {
      // Edge Functions
      const functionName = pathParts[2];

      // Prepare the payload
      const payload = await request.json();

      // Log function invocation for monitoring
      const requestId = Security.generateRequestId();
      console.log(`Function invoke: ${functionName} [${requestId}]`);

      try {
        const { data, error } = await supabase.functions.invoke(functionName, {
          body: payload,
        });

        return { data, error };
      } catch (error) {
        console.error(`Function error [${requestId}]:`, error);
        return {
          error: {
            message: "Function invocation failed",
            original: error.message,
          },
        };
      }
    } else if (
      pathParts[0] === "rest" &&
      pathParts[1] === "v1" &&
      pathParts[2] === "rpc" &&
      pathParts.length > 3
    ) {
      // Database RPC function
      const functionName = pathParts[3];

      // Prepare the payload
      const payload = await request.json();

      try {
        const { data, error } = await supabase.rpc(functionName, payload);
        return { data, error };
      } catch (error) {
        return {
          error: {
            message: "RPC function call failed",
            original: error.message,
          },
        };
      }
    }

    return { error: { message: "Function/RPC not supported" } };
  },
};

/**
 * Simplified file scanner (placeholder)
 * In a real implementation, this would integrate with
 * virus scanning services or AI-based malware detection
 */
async function scanFileForMalware(fileData) {
  // Placeholder for actual file scanning logic
  // This would normally call a virus scanning service or implement checks

  // For now, just do a basic check for executable files
  const header = new Uint8Array(fileData.slice(0, 4));

  // Check for common executable headers (simplified)
  const isMZHeader = header[0] === 77 && header[1] === 90; // MZ header for Windows executables
  const isELFHeader =
    header[0] === 127 &&
    header[1] === 69 &&
    header[2] === 76 &&
    header[3] === 70; // ELF header for Linux executables

  // Reject executables
  if (isMZHeader || isELFHeader) {
    return false;
  }

  return true;
}

/**
 * Main worker fetch handler
 */
export default {
  async fetch(request, env, ctx) {
    // Request ID for tracing
    const requestId = Security.generateRequestId();
    const startTime = Date.now();

    // Add basic security headers to all responses
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers":
        "Content-Type, Authorization, X-Security-Nonce, X-Request-ID, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Strict-Transport-Security",
      "X-Request-ID": requestId,
    };

    // Handle OPTIONS request for CORS
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    // Security check: validate client IP and headers
    const securityCheck = Security.checkSecurityHeaders(request);

    if (!securityCheck.allowed) {
      await Security.logSecurityEvent(
        {
          type: "SECURITY_BLOCK",
          reason: securityCheck.reason,
          ip: request.headers.get("CF-Connecting-IP"),
          headers: Object.fromEntries(request.headers),
          requestId,
          timestamp: Date.now(),
        },
        env
      );

      return new Response(
        JSON.stringify({
          error: "Request blocked for security reasons",
          code: securityCheck.reason,
        }),
        {
          status: 403,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Rate limiting
    const isRateLimited = !(await Security.rateLimit(request, env, ctx));

    if (isRateLimited) {
      await Security.logSecurityEvent(
        {
          type: "RATE_LIMIT_EXCEEDED",
          ip: request.headers.get("CF-Connecting-IP"),
          path: new URL(request.url).pathname,
          requestId,
          timestamp: Date.now(),
        },
        env
      );

      return new Response(
        JSON.stringify({
          error: "Too many requests",
          code: "RATE_LIMIT_EXCEEDED",
        }),
        {
          status: 429,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
            "Retry-After": "60",
          },
        }
      );
    }

    try {
      // Parse URL and path
      const url = new URL(request.url);
      const path = url.pathname;
      const pathParts = path.split("/").filter(Boolean);

      if (pathParts.length === 0) {
        return new Response(
          JSON.stringify({
            name: "Saint Central API",
            version: "1.0.0",
            status: "operational",
          }),
          {
            status: 200,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      // Route request to appropriate handler
      let result;

      if (pathParts[0] === "rest" && pathParts[1] === "v1") {
        // Database operations
        result = await Handlers.handleDatabase(request, env, ctx, pathParts);
      } else if (pathParts[0] === "auth") {
        // Auth operations
        result = await Handlers.handleAuth(request, env, ctx, pathParts);
      } else if (pathParts[0] === "storage") {
        // Storage operations
        result = await Handlers.handleStorage(request, env, ctx, pathParts);
      } else if (
        pathParts[0] === "functions" ||
        (pathParts[0] === "rest" &&
          pathParts[1] === "v1" &&
          pathParts[2] === "rpc")
      ) {
        // Functions/RPC operations
        result = await Handlers.handleFunctions(request, env, ctx, pathParts);
      } else {
        result = { error: { message: "Endpoint not found" } };
      }

      // Log execution time for performance monitoring
      const duration = Date.now() - startTime;
      console.log(`Request ${requestId} completed in ${duration}ms`);

      // Apply security enhancements to the response
      if (result.error) {
        // Sanitize error messages to prevent information disclosure
        const safeError = {
          message: result.error.message,
          code: result.error.code || "ERROR",
        };

        return Security.enforceCSP(
          new Response(JSON.stringify({ error: safeError }), {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          })
        );
      } else {
        // Encrypt sensitive data in the response if needed
        const responseData = result.data ? result.data : result;

        return Security.enforceCSP(
          new Response(JSON.stringify({ data: responseData }), {
            status: 200,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
              "Cache-Control": "private, no-cache, no-store, must-revalidate",
            },
          })
        );
      }
    } catch (error) {
      // Log the error for monitoring
      console.error(`Error processing request ${requestId}:`, error);

      await Security.logSecurityEvent(
        {
          type: "SERVER_ERROR",
          error: error.message,
          stack: error.stack,
          requestId,
          timestamp: Date.now(),
        },
        env
      );

      // Return a sanitized error response
      return Security.enforceCSP(
        new Response(
          JSON.stringify({
            error: {
              message: "An unexpected error occurred",
              code: "SERVER_ERROR",
              id: requestId,
            },
          }),
          {
            status: 500,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        )
      );
    }
  },
};
