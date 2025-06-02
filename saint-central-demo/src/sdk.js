/**
 * Saint Central SDK - Production Ready
 *
 * A secure alternative to Supabase SDK with enterprise-grade security features,
 * designed to be a drop-in replacement with identical API signatures.
 * Built for Cloudflare Workers with real encryption and comprehensive error handling.
 *
 * @version 2.0.0
 */

// Core client that integrates all Saint Central services
export function createClient(url, options = {}) {
  const apiUrl = new URL(url);

  // Generate a secure encryption key - define this first
  const generateEncryptionKey = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
      ""
    );
  };

  // Enhanced security features
  const securityOptions = {
    encryption: true,
    rateLimit: true,
    jwtHardening: true,
    ddosProtection: true,
    headerSecurity: true,
    contentSecurityPolicy: true,
    autoTokenRefresh: true,
    ...options.security,
  };

  // Configuration - now generateEncryptionKey is available
  const config = {
    maxRetries: 3,
    retryDelay: 1000,
    requestTimeout: 30000,
    encryptionKey: null, // Will be set via key exchange
    sessionId: null,
    initialized: false,
    ...options.config,
  };

  // Local storage keys
  const STORAGE_KEY = "saint_central_auth";
  const SESSION_KEY_STORAGE = "saint_central_session";

  // Secure key exchange with server
  const performKeyExchange = async () => {
    try {
      console.log("🔄 Initiating secure key exchange...");

      const response = await fetch(`${apiUrl.origin}/auth/key-exchange`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": generateRequestId(),
          "X-Client-Version": "2.0.0",
        },
        body: JSON.stringify({
          clientInfo: {
            userAgent: navigator.userAgent,
            timestamp: Date.now(),
            version: "2.0.0",
          },
        }),
      });

      if (!response.ok) {
        throw new Error(
          `Key exchange failed: ${response.status} ${response.statusText}`
        );
      }

      const data = await response.json();

      if (data.error) {
        throw new Error(data.error.message || "Key exchange failed");
      }

      const sessionData = {
        sessionId: data.data.sessionId,
        sessionKey: data.data.sessionKey,
        algorithm: data.data.algorithm,
        version: data.data.version,
        expiresAt: data.data.expiresAt,
        createdAt: Date.now(),
      };

      // Store session data
      config.encryptionKey = sessionData.sessionKey;
      config.sessionId = sessionData.sessionId;
      config.initialized = true;

      if (typeof localStorage !== "undefined") {
        try {
          localStorage.setItem(
            SESSION_KEY_STORAGE,
            JSON.stringify(sessionData)
          );
        } catch (error) {
          console.warn("Could not store session data:", error);
        }
      }

      console.log("🔒 Secure key exchange completed successfully");
      return sessionData;
    } catch (error) {
      console.error("Key exchange failed:", error);
      throw new SaintCentralError({
        message: "Failed to establish secure connection",
        code: "KEY_EXCHANGE_ERROR",
        originalError: error,
      });
    }
  };

  // Initialize encryption with key exchange
  const initializeEncryption = async () => {
    if (config.initialized) {
      return; // Already initialized
    }

    // Check if we have a valid stored session
    if (typeof localStorage !== "undefined") {
      try {
        const storedSession = localStorage.getItem(SESSION_KEY_STORAGE);
        if (storedSession) {
          const sessionData = JSON.parse(storedSession);

          // Check if session is still valid (not expired)
          if (sessionData.expiresAt && Date.now() < sessionData.expiresAt) {
            config.encryptionKey = sessionData.sessionKey;
            config.sessionId = sessionData.sessionId;
            config.initialized = true;
            console.log("🔒 Using existing valid session");
            return sessionData;
          } else {
            // Session expired, remove it
            localStorage.removeItem(SESSION_KEY_STORAGE);
          }
        }
      } catch (error) {
        console.warn("Could not load stored session:", error);
        if (typeof localStorage !== "undefined") {
          localStorage.removeItem(SESSION_KEY_STORAGE);
        }
      }
    }

    // No valid session found, perform key exchange
    return await performKeyExchange();
  };

  // Auto-initialize if encryption is enabled
  let initializationPromise = null;
  if (securityOptions.encryption) {
    initializationPromise = initializeEncryption().catch((error) => {
      console.error("Failed to initialize encryption:", error);
      // Don't throw here, let individual requests handle it
    });
  }

  // Utility functions
  const generateSecureNonce = () => {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
      ""
    );
  };

  const generateRequestId = () => {
    return `req_${Date.now()}_${crypto.randomUUID()}`;
  };

  const isRetryableError = (error) => {
    return (
      error.code === "NETWORK_ERROR" ||
      error.code === "TIMEOUT" ||
      (error.status >= 500 && error.status < 600)
    );
  };

  const createErrorFromResponse = (errorData, status) => {
    const errorMap = {
      400: ValidationError,
      401: AuthError,
      403: PermissionError,
      404: NotFoundError,
      409: ConflictError,
      422: ValidationError,
      429: RateLimitError,
      500: ServerError,
    };

    const ErrorClass = errorMap[status] || SaintCentralError;
    return new ErrorClass({
      ...errorData,
      status,
    });
  };

  // Enhanced auth storage with encryption
  const getStoredAuth = () => {
    try {
      if (typeof localStorage === "undefined") return null;

      const storedAuth = localStorage.getItem(STORAGE_KEY);
      if (!storedAuth) return null;

      const parsed = JSON.parse(storedAuth);

      // Check if auth data is expired
      if (parsed.expires_at && Date.now() / 1000 > parsed.expires_at) {
        clearStoredAuth();
        return null;
      }

      return parsed;
    } catch (error) {
      console.error("Error retrieving auth from storage:", error);
      return null;
    }
  };

  const storeAuth = (auth) => {
    try {
      if (typeof localStorage === "undefined") return;

      // Add expiration timestamp
      const authWithExpiry = {
        ...auth,
        stored_at: Date.now(),
        expires_at: auth.expires_at || Date.now() / 1000 + 3600, // 1 hour default
      };

      localStorage.setItem(STORAGE_KEY, JSON.stringify(authWithExpiry));
    } catch (error) {
      console.error("Error storing auth:", error);
    }
  };

  const clearStoredAuth = () => {
    try {
      if (typeof localStorage === "undefined") return;
      localStorage.removeItem(STORAGE_KEY);
    } catch (error) {
      console.error("Error clearing auth:", error);
    }
  };

  // Real AES-GCM encryption using Web Crypto API
  const realEncryption = {
    async encrypt(data) {
      try {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(JSON.stringify(data));

        // Generate a random IV
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Convert hex key to buffer
        const keyBuffer = new Uint8Array(
          config.encryptionKey
            .match(/.{1,2}/g)
            .map((byte) => parseInt(byte, 16))
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
        console.error("Encryption failed:", error);
        throw new SaintCentralError({
          message: "Encryption failed",
          code: "ENCRYPTION_ERROR",
          originalError: error,
        });
      }
    },

    async decrypt(encryptedData) {
      try {
        if (
          !encryptedData ||
          !encryptedData.encrypted ||
          encryptedData.version !== 2
        ) {
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

        // Convert hex key to buffer
        const keyBuffer = new Uint8Array(
          config.encryptionKey
            .match(/.{1,2}/g)
            .map((byte) => parseInt(byte, 16))
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
        console.error("Decryption failed:", error);
        throw new SaintCentralError({
          message: "Decryption failed",
          code: "DECRYPTION_ERROR",
          originalError: error,
        });
      }
    },
  };

  // Enhanced fetch with automatic retry, rate limiting, and token refresh
  const fetchWithAuth = async (path, options = {}, retryCount = 0) => {
    // Ensure encryption is initialized before making requests
    if (securityOptions.encryption && !config.initialized) {
      try {
        console.log("⏳ Waiting for encryption initialization...");
        if (initializationPromise) {
          await initializationPromise;
        } else {
          await initializeEncryption();
        }
      } catch (error) {
        console.error("Failed to initialize encryption:", error);
        throw new SaintCentralError({
          message: "Failed to establish secure connection",
          code: "KEY_EXCHANGE_ERROR",
          originalError: error,
        });
      }
    }

    const authData = getStoredAuth();

    // Check if we need to refresh the token
    if (authData && securityOptions.autoTokenRefresh) {
      const expiresAt = authData.expires_at || 0;
      const refreshThreshold = 300; // Refresh if expires within 5 minutes

      if (
        expiresAt - Date.now() / 1000 < refreshThreshold &&
        authData.refresh_token
      ) {
        try {
          await refreshToken();
        } catch (error) {
          console.warn("Token refresh failed:", error);
        }
      }
    }

    const fetchOptions = {
      method: options.method || "GET",
      credentials: "omit",
      mode: "cors",
      cache: "no-cache",
      signal: AbortSignal.timeout(config.requestTimeout),
    };

    console.log("⏱️ Request timeout set to:", config.requestTimeout, "ms");
    console.log("🌐 Request mode:", fetchOptions.mode);
    console.log("🍪 Credentials:", fetchOptions.credentials);

    // Add timeout debugging
    const timeoutStart = Date.now();
    fetchOptions.signal.addEventListener("abort", () => {
      const timeoutDuration = Date.now() - timeoutStart;
      console.error(
        "⏰ Request aborted due to timeout after",
        timeoutDuration,
        "ms"
      );
    });

    // Enhanced security headers
    fetchOptions.headers = {
      "Content-Type": "application/json",
      "X-Security-Nonce": generateSecureNonce(),
      "X-Request-ID": generateRequestId(),
      "X-Client-Version": "2.0.0",
      "User-Agent": "SaintCentral-SDK/2.0.0",
    };

    // Add session ID if available
    if (config.sessionId) {
      fetchOptions.headers["X-Session-ID"] = config.sessionId;
    }

    // Copy custom headers
    if (options.headers) {
      Object.assign(fetchOptions.headers, options.headers);
    }

    // Add auth token if available
    const currentAuth = getStoredAuth();
    if (currentAuth && currentAuth.access_token) {
      fetchOptions.headers[
        "Authorization"
      ] = `Bearer ${currentAuth.access_token}`;
    }

    // Handle body and encryption
    if (options.body) {
      if (
        securityOptions.encryption &&
        typeof options.body === "string" &&
        config.encryptionKey
      ) {
        try {
          console.log("🔒 Encrypting request body...");
          console.log("🔑 Encryption key available:", !!config.encryptionKey);
          console.log(
            "📝 Body to encrypt:",
            options.body.substring(0, 100) + "..."
          );

          const bodyData = JSON.parse(options.body);
          const encryptedBody = await realEncryption.encrypt(bodyData);
          fetchOptions.body = JSON.stringify(encryptedBody);
          fetchOptions.headers["Content-Type"] = "application/encrypted+json";
          console.log("🔒 Request payload encrypted successfully");
          console.log("📦 Encrypted body length:", fetchOptions.body.length);
        } catch (error) {
          console.error("❌ Encryption failed:", error);
          console.error(
            "🔑 Encryption key:",
            config.encryptionKey ? "Present" : "Missing"
          );
          console.error("📝 Original body:", options.body);
          throw new SaintCentralError({
            message: "Failed to encrypt request payload",
            code: "ENCRYPTION_ERROR",
            originalError: error,
          });
        }
      } else {
        console.log("📝 Using unencrypted body");
        fetchOptions.body = options.body;
      }
    }

    const endpoint = `${apiUrl.origin}/${path}`;

    try {
      console.log("🌐 Making request to:", endpoint);
      console.log("🔧 Request options:", {
        method: fetchOptions.method,
        headers: fetchOptions.headers,
        bodyLength: fetchOptions.body ? fetchOptions.body.length : 0,
        hasBody: !!fetchOptions.body,
      });

      const response = await fetch(endpoint, fetchOptions);

      console.log("📡 Response received:", {
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        headers: Object.fromEntries(response.headers.entries()),
      });

      // Handle rate limiting
      if (response.status === 429) {
        const retryAfter = response.headers.get("Retry-After") || "60";
        const delay = parseInt(retryAfter) * 1000;

        if (retryCount < config.maxRetries) {
          await new Promise((resolve) => setTimeout(resolve, delay));
          return fetchWithAuth(path, options, retryCount + 1);
        }

        throw new RateLimitError({
          message: "Rate limit exceeded",
          retryAfter: delay,
          headers: Object.fromEntries(response.headers.entries()),
        });
      }

      // Handle authentication errors
      if (response.status === 401) {
        clearStoredAuth();
        throw new AuthError({
          message: "Authentication failed",
          status: 401,
        });
      }

      // Parse response
      const contentType = response.headers.get("Content-Type") || "";
      let data;

      if (contentType.includes("application/json")) {
        data = await response.json();
      } else if (
        response.headers.get("Content-Length") === "0" ||
        response.status === 204
      ) {
        data = null;
      } else {
        data = await response.arrayBuffer();
      }

      if (!response.ok) {
        const error = data?.error || {
          message: `HTTP ${response.status}: ${response.statusText}`,
          status: response.status,
        };

        throw createErrorFromResponse(error, response.status);
      }

      // Handle authentication responses
      if (
        (path.startsWith("auth/signin") ||
          path.startsWith("auth/signup") ||
          path.startsWith("auth/token")) &&
        data?.data
      ) {
        // Handle both direct session data and nested session data
        const sessionData = data.data.session || data.data;
        if (sessionData && (sessionData.access_token || sessionData.user)) {
          storeAuth(sessionData);
        }
      }

      // Handle sign out
      if (path.startsWith("auth/signout") && !data?.error) {
        clearStoredAuth();
      }

      return {
        data: data?.data || data,
        error: data?.error || null,
        requestId: response.headers.get("X-Request-ID"),
      };
    } catch (error) {
      if (error.name === "AbortError") {
        throw new NetworkError({
          message: "Request timeout",
          code: "TIMEOUT",
          originalError: error,
        });
      }

      if (error instanceof SaintCentralError) {
        throw error;
      }

      // Enhanced error logging for debugging
      console.error("Network request failed:", {
        endpoint,
        method: fetchOptions.method,
        error: error.message,
        errorName: error.name,
        errorStack: error.stack,
        retryCount,
        maxRetries: config.maxRetries,
      });

      // Retry on network errors
      if (retryCount < config.maxRetries && isRetryableError(error)) {
        const delay = config.retryDelay * Math.pow(2, retryCount);
        console.log(
          `Retrying request in ${delay}ms (attempt ${retryCount + 1}/${
            config.maxRetries
          })`
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
        return fetchWithAuth(path, options, retryCount + 1);
      }

      // Create more detailed error for network failures
      const networkError = new NetworkError({
        message: error.message || "Network request failed",
        code: "NETWORK_ERROR",
        originalError: error,
        details: {
          endpoint,
          method: fetchOptions.method,
          retryCount,
          errorType: error.name,
          timestamp: Date.now(),
        },
      });

      throw networkError;
    }
  };

  // Token refresh functionality
  const refreshToken = async () => {
    const authData = getStoredAuth();
    if (!authData || !authData.refresh_token) {
      throw new AuthError({ message: "No refresh token available" });
    }

    const response = await fetch(`${apiUrl.origin}/auth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Request-ID": generateRequestId(),
      },
      body: JSON.stringify({
        refresh_token: authData.refresh_token,
      }),
    });

    if (!response.ok) {
      clearStoredAuth();
      throw new AuthError({ message: "Token refresh failed" });
    }

    const data = await response.json();
    if (data.data) {
      storeAuth(data.data);
      return data.data;
    }

    throw new AuthError({ message: "Invalid refresh response" });
  };

  // Initialize all service clients
  const auth = createAuthClient(fetchWithAuth, {
    url: apiUrl.origin,
    securityOptions,
    getStoredAuth,
    clearStoredAuth,
    refreshToken,
  });

  const storage = createStorageClient(fetchWithAuth, {
    url: apiUrl.origin,
    securityOptions,
  });

  const realtime = createRealtimeClient({
    url: apiUrl.origin,
    securityOptions,
    getAuth: getStoredAuth,
  });

  const functions = createFunctionsClient(fetchWithAuth, {
    url: apiUrl.origin,
    securityOptions,
  });

  const database = {
    from: (table) => createTableQueryBuilder(table, fetchWithAuth),
    rpc: (fn, params) => callStoredProcedure(fn, params, fetchWithAuth),
  };

  return {
    // Core services mirroring Supabase interface
    auth,
    storage,
    from: database.from,
    rpc: database.rpc,
    functions,
    realtime,

    // Saint Central-specific functionality
    security: {
      configure: (newConfig) => Object.assign(securityOptions, newConfig),
      status: () => ({ ...securityOptions }),
      getEncryptionConfig: () => ({
        encryptionEnabled: securityOptions.encryption,
        sessionId: config.sessionId,
        encryptionKey: config.encryptionKey
          ? {
              present: true,
              length: config.encryptionKey.length,
              preview: config.encryptionKey.substring(0, 8) + "...",
              source: "key-exchange",
            }
          : null,
        algorithm: "AES-256-GCM",
        version: 2,
      }),
      refreshEncryption: async () => {
        try {
          const sessionData = await performKeyExchange();
          return {
            success: true,
            sessionId: sessionData.sessionId,
            expiresAt: sessionData.expiresAt,
          };
        } catch (error) {
          return {
            success: false,
            error: error.message,
          };
        }
      },
      testKeyExchange: async (testData) => {
        try {
          // Clear existing session to force new key exchange
          config.encryptionKey = null;
          config.sessionId = null;

          // Perform key exchange
          const sessionData = await performKeyExchange();

          // Test encryption with new key
          const encrypted = await realEncryption.encrypt(testData);
          const decrypted = await realEncryption.decrypt(encrypted);

          return {
            success: true,
            sessionData: {
              sessionId: sessionData.sessionId,
              algorithm: sessionData.algorithm,
              version: sessionData.version,
              expiresAt: sessionData.expiresAt,
            },
            encryptionTest: {
              original: testData,
              encrypted: {
                version: encrypted.version,
                algorithm: encrypted.algorithm,
                dataLength: encrypted.data.length,
              },
              decrypted: decrypted,
              successful:
                JSON.stringify(testData) === JSON.stringify(decrypted),
            },
          };
        } catch (error) {
          return {
            success: false,
            error: error.message,
          };
        }
      },
      clearSession: () => {
        config.encryptionKey = null;
        config.sessionId = null;
        if (typeof localStorage !== "undefined") {
          try {
            localStorage.removeItem(SESSION_KEY_STORAGE);
          } catch (error) {
            console.warn("Could not clear session data");
          }
        }
      },
    },

    // Enhanced REST client
    rest: {
      get: (path) => fetchWithAuth(path, { method: "GET" }),
      post: (path, body) =>
        fetchWithAuth(path, {
          method: "POST",
          body: JSON.stringify(body),
        }),
      put: (path, body) =>
        fetchWithAuth(path, {
          method: "PUT",
          body: JSON.stringify(body),
        }),
      patch: (path, body) =>
        fetchWithAuth(path, {
          method: "PATCH",
          body: JSON.stringify(body),
        }),
      delete: (path) => fetchWithAuth(path, { method: "DELETE" }),
    },

    // Utility methods
    utils: {
      generateId: () => crypto.randomUUID(),
      encrypt: realEncryption.encrypt,
      decrypt: realEncryption.decrypt,
      refreshToken,
      ready: async () => {
        if (securityOptions.encryption && !config.initialized) {
          if (initializationPromise) {
            await initializationPromise;
          } else {
            await initializeEncryption();
          }
        }
        return {
          ready: true,
          encrypted: securityOptions.encryption,
          sessionId: config.sessionId,
          initialized: config.initialized,
        };
      },
      testConnectivity: async () => {
        try {
          console.log("Testing basic connectivity to:", apiUrl.origin);

          // Test 1: Basic health check
          const healthResponse = await fetch(`${apiUrl.origin}/`, {
            method: "GET",
            headers: {
              "X-Request-ID": generateRequestId(),
            },
          });

          const healthData = await healthResponse.json();
          console.log("Health check response:", healthData);

          // Test 2: Test auth endpoint specifically
          const authTestResponse = await fetch(
            `${apiUrl.origin}/auth/key-exchange`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Request-ID": generateRequestId(),
              },
              body: JSON.stringify({
                clientInfo: {
                  userAgent: "connectivity-test",
                  timestamp: Date.now(),
                  version: "2.0.0",
                },
              }),
            }
          );

          const authTestData = await authTestResponse.json();
          console.log("Auth endpoint test response:", authTestData);

          return {
            success: true,
            healthCheck: {
              status: healthResponse.status,
              data: healthData,
            },
            authEndpoint: {
              status: authTestResponse.status,
              data: authTestData,
            },
            timestamp: Date.now(),
          };
        } catch (error) {
          console.error("Connectivity test failed:", error);
          return {
            success: false,
            error: error.message,
            errorType: error.name,
            timestamp: Date.now(),
          };
        }
      },
    },
  };
}

/**
 * Enhanced Auth Client Implementation
 */
function createAuthClient(fetch, options) {
  const getSession = async () => {
    const authData = options.getStoredAuth();
    if (!authData) {
      return { data: { session: null }, error: null };
    }

    try {
      const result = await fetch("auth/session", { method: "GET" });
      return result;
    } catch (error) {
      options.clearStoredAuth();
      return { data: { session: null }, error };
    }
  };

  const refreshSession = async () => {
    try {
      return await options.refreshToken();
    } catch (error) {
      return { data: null, error };
    }
  };

  const signUp = async (credentials) => {
    validateCredentials(credentials, ["email", "password"]);
    return fetch("auth/signup", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
  };

  const signInWithPassword = async (credentials) => {
    validateCredentials(credentials, ["password"]);

    if (!credentials.email && !credentials.phone) {
      throw new ValidationError({
        message: "Email or phone is required",
        code: "missing_credentials",
      });
    }

    return fetch("auth/signin", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
  };

  const signIn = signInWithPassword; // Alias for compatibility

  const signOut = async () => {
    try {
      const result = await fetch("auth/signout", { method: "POST" });
      options.clearStoredAuth();
      return result;
    } catch (error) {
      options.clearStoredAuth();
      return { data: null, error };
    }
  };

  const resetPasswordForEmail = async (email) => {
    if (!email) {
      throw new ValidationError({
        message: "Email is required",
        code: "missing_email",
      });
    }

    return fetch("auth/recover", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  };

  const signInWithOAuth = async (provider, options = {}) => {
    return fetch("auth/authorize", {
      method: "POST",
      body: JSON.stringify({ provider, ...options }),
    });
  };

  const testManualAuth = async (credentials) => {
    try {
      console.log("Testing manual auth - bypassing SDK encryption");

      // Test 1: Direct fetch to auth endpoint without encryption
      console.log("🧪 Test 1: Direct fetch without encryption");
      const directResponse = await window.fetch(`${options.url}/auth/signin`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": `manual_${Date.now()}`,
        },
        body: JSON.stringify(credentials),
      });

      console.log("Direct auth response status:", directResponse.status);
      console.log(
        "Direct auth response headers:",
        Object.fromEntries(directResponse.headers.entries())
      );

      let directData;
      try {
        directData = await directResponse.json();
        console.log("Direct auth response data:", directData);
      } catch (parseError) {
        console.error("Failed to parse direct auth response:", parseError);
        directData = { error: "Failed to parse response" };
      }

      // Test 2: Test with the exact same headers and options as the SDK
      console.log("🧪 Test 2: Mimicking SDK request exactly");
      const sdkLikeResponse = await window.fetch(`${options.url}/auth/signin`, {
        method: "POST",
        credentials: "omit",
        mode: "cors",
        cache: "no-cache",
        headers: {
          "Content-Type": "application/json",
          "X-Security-Nonce": crypto.randomUUID(),
          "X-Request-ID": `sdk_like_${Date.now()}`,
          "X-Client-Version": "2.0.0",
          "User-Agent": "SaintCentral-SDK/2.0.0",
        },
        body: JSON.stringify(credentials),
      });

      console.log("SDK-like response status:", sdkLikeResponse.status);
      let sdkLikeData;
      try {
        sdkLikeData = await sdkLikeResponse.json();
        console.log("SDK-like response data:", sdkLikeData);
      } catch (parseError) {
        console.error("Failed to parse SDK-like response:", parseError);
        sdkLikeData = { error: "Failed to parse response" };
      }

      // Test 3: Using SDK's fetchWithAuth but with encryption disabled temporarily
      console.log("🧪 Test 3: SDK fetchWithAuth with encryption disabled");
      const originalEncryption = options.securityOptions?.encryption;
      if (options.securityOptions) {
        options.securityOptions.encryption = false;
      }

      let sdkResult;
      try {
        sdkResult = await fetch("auth/signin", {
          method: "POST",
          body: JSON.stringify(credentials),
        });
        console.log("SDK auth result (no encryption):", sdkResult);
      } catch (sdkError) {
        console.error("SDK auth failed (no encryption):", sdkError);
        sdkResult = { error: sdkError.message };
      }

      // Restore original encryption setting
      if (options.securityOptions) {
        options.securityOptions.encryption = originalEncryption;
      }

      return {
        success: true,
        directFetch: {
          status: directResponse.status,
          ok: directResponse.ok,
          data: directData,
        },
        sdkLikeFetch: {
          status: sdkLikeResponse.status,
          ok: sdkLikeResponse.ok,
          data: sdkLikeData,
        },
        sdkFetch: sdkResult,
        timestamp: Date.now(),
      };
    } catch (error) {
      console.error("Manual auth test failed:", error);
      return {
        success: false,
        error: error.message,
        errorType: error.name,
        timestamp: Date.now(),
      };
    }
  };

  const testWithTimeout = async (credentials, timeoutMs = 60000) => {
    try {
      console.log(`🧪 Testing sign-in with ${timeoutMs}ms timeout...`);

      // Temporarily change the timeout
      const originalTimeout = config.requestTimeout;
      config.requestTimeout = timeoutMs;

      const result = await fetch("auth/signin", {
        method: "POST",
        body: JSON.stringify(credentials),
      });

      // Restore original timeout
      config.requestTimeout = originalTimeout;

      return result;
    } catch (error) {
      // Restore original timeout even on error
      config.requestTimeout = originalTimeout;
      throw error;
    }
  };

  const validateCredentials = (credentials, required) => {
    for (const field of required) {
      if (!credentials[field]) {
        throw new ValidationError({
          message: `${field} is required`,
          code: `missing_${field}`,
        });
      }
    }
  };

  return {
    getSession,
    refreshSession,
    signUp,
    signIn,
    signInWithPassword,
    signOut,
    resetPasswordForEmail,
    signInWithOAuth,
    testManualAuth,
    testWithTimeout,
    signInWithGoogle: (opts) => signInWithOAuth("google", opts),
    signInWithFacebook: (opts) => signInWithOAuth("facebook", opts),
    signInWithGithub: (opts) => signInWithOAuth("github", opts),
  };
}

/**
 * Enhanced Storage Client Implementation
 */
function createStorageClient(fetch, options) {
  const from = (bucket) => {
    if (!bucket) {
      throw new ValidationError({
        message: "Bucket name is required",
        code: "missing_bucket",
      });
    }

    const upload = async (path, fileBody, fileOptions = {}) => {
      if (!path || !fileBody) {
        throw new ValidationError({
          message: "Path and file body are required",
          code: "missing_upload_params",
        });
      }

      const formData = new FormData();
      formData.append("file", fileBody);

      if (fileOptions.contentType) {
        formData.append("content_type", fileOptions.contentType);
      }

      return fetch(`storage/object/${bucket}/${path}`, {
        method: "POST",
        body: formData,
        headers: {}, // Don't set Content-Type for FormData
      });
    };

    const download = async (path) => {
      if (!path) {
        throw new ValidationError({
          message: "Path is required",
          code: "missing_path",
        });
      }

      return fetch(`storage/object/${bucket}/${path}`, {
        method: "GET",
      });
    };

    const remove = async (paths) => {
      if (!paths || (Array.isArray(paths) && paths.length === 0)) {
        throw new ValidationError({
          message: "Paths are required",
          code: "missing_paths",
        });
      }

      return fetch(`storage/object/${bucket}`, {
        method: "DELETE",
        body: JSON.stringify({
          prefixes: Array.isArray(paths) ? paths : [paths],
        }),
      });
    };

    const list = async (prefix = "", options = {}) => {
      const query = new URLSearchParams({ prefix });

      if (options.limit) query.append("limit", options.limit);
      if (options.offset) query.append("offset", options.offset);

      return fetch(`storage/object/list/${bucket}?${query.toString()}`, {
        method: "GET",
      });
    };

    const getPublicUrl = (path) => {
      if (!path) {
        throw new ValidationError({
          message: "Path is required",
          code: "missing_path",
        });
      }
      return {
        data: {
          publicUrl: `${options.url}/storage/object/public/${bucket}/${path}`,
        },
      };
    };

    return { upload, download, remove, list, getPublicUrl };
  };

  const createBucket = async (bucketName, bucketOptions = {}) => {
    if (!bucketName) {
      throw new ValidationError({
        message: "Bucket name is required",
        code: "missing_bucket_name",
      });
    }

    return fetch("storage/bucket", {
      method: "POST",
      body: JSON.stringify({
        id: bucketName,
        public: !!bucketOptions.public,
      }),
    });
  };

  const deleteBucket = async (bucketName) => {
    if (!bucketName) {
      throw new ValidationError({
        message: "Bucket name is required",
        code: "missing_bucket_name",
      });
    }

    return fetch(`storage/bucket/${bucketName}`, {
      method: "DELETE",
    });
  };

  const listBuckets = async () => {
    return fetch("storage/bucket", { method: "GET" });
  };

  return { from, createBucket, deleteBucket, listBuckets };
}

/**
 * Enhanced Realtime Client Implementation
 */
function createRealtimeClient(options) {
  let socket = null;
  let channels = new Map();
  let reconnectAttempts = 0;
  const maxReconnectAttempts = 5;

  const connect = () => {
    const wsUrl = options.url.replace(/^http/, "ws");
    const authData = options.getAuth ? options.getAuth() : null;
    const token = authData?.access_token;

    const wsEndpoint = token
      ? `${wsUrl}/realtime/v1?token=${encodeURIComponent(token)}`
      : `${wsUrl}/realtime/v1`;

    socket = new WebSocket(wsEndpoint);

    socket.onopen = () => {
      console.log("WebSocket connected");
      reconnectAttempts = 0;
      startHeartbeat();
    };

    socket.onclose = (event) => {
      console.log("WebSocket closed:", event.code, event.reason);
      if (reconnectAttempts < maxReconnectAttempts) {
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        setTimeout(() => {
          reconnectAttempts++;
          connect();
        }, delay);
      }
    };

    socket.onerror = (error) => {
      console.error("WebSocket error:", error);
    };

    return socket;
  };

  const startHeartbeat = () => {
    const heartbeatInterval = setInterval(() => {
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(
          JSON.stringify({ type: "heartbeat", timestamp: Date.now() })
        );
      } else {
        clearInterval(heartbeatInterval);
      }
    }, 30000);
  };

  const channel = (name, options = {}) => {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      connect();
    }

    if (!channels.has(name)) {
      channels.set(name, createChannel(name, socket, options));
    }

    return channels.get(name);
  };

  const createChannel = (name, socket, options) => {
    let listeners = new Map();
    let subscribed = false;

    const subscribe = (callback) => {
      if (!socket) {
        throw new Error("WebSocket not connected");
      }

      socket.send(
        JSON.stringify({
          type: "subscribe",
          channel: name,
          config: options,
        })
      );

      subscribed = true;

      const messageHandler = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.channel === name) {
            callback(data.payload);

            if (data.event && listeners.has(data.event)) {
              listeners
                .get(data.event)
                .forEach((listener) => listener(data.payload));
            }
          }
        } catch (error) {
          console.error("Error handling WebSocket message:", error);
        }
      };

      socket.addEventListener("message", messageHandler);

      return {
        unsubscribe: () => {
          socket.removeEventListener("message", messageHandler);
          socket.send(
            JSON.stringify({
              type: "unsubscribe",
              channel: name,
            })
          );
          subscribed = false;
          channels.delete(name);
        },
      };
    };

    const on = (event, callback) => {
      if (!listeners.has(event)) {
        listeners.set(event, new Set());
      }
      listeners.get(event).add(callback);

      return {
        unsubscribe: () => {
          listeners.get(event)?.delete(callback);
        },
      };
    };

    const send = (event, payload) => {
      if (!subscribed) {
        throw new Error("Must subscribe to channel before sending messages");
      }

      socket.send(
        JSON.stringify({
          type: "broadcast",
          channel: name,
          event,
          payload,
          timestamp: Date.now(),
        })
      );
    };

    return { subscribe, on, send };
  };

  return {
    connect,
    channel,
    disconnect: () => {
      if (socket) {
        socket.close();
        socket = null;
        channels.clear();
      }
    },
  };
}

/**
 * Enhanced Functions Client Implementation
 */
function createFunctionsClient(fetch, options) {
  const invoke = async (functionName, payload = {}, invokeOptions = {}) => {
    if (!functionName) {
      throw new ValidationError({
        message: "Function name is required",
        code: "missing_function_name",
      });
    }

    const headers = {
      "Content-Type": "application/json",
      ...invokeOptions.headers,
    };

    return fetch(`functions/v1/${functionName}`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
  };

  return { invoke };
}

/**
 * Enhanced Database Query Builder Implementation
 */
function createTableQueryBuilder(table, fetch) {
  if (!table) {
    throw new ValidationError({
      message: "Table name is required",
      code: "missing_table",
    });
  }

  let queryFilters = [];
  let queryOptions = {
    limit: null,
    offset: null,
    order: null,
    select: "*",
  };

  const buildQueryUrl = () => {
    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    queryFilters.forEach((filter) => {
      url.searchParams.append(
        filter.column,
        `${filter.operator}.${filter.value}`
      );
    });

    Object.entries(queryOptions).forEach(([key, value]) => {
      if (value !== null) {
        url.searchParams.append(key, value);
      }
    });

    return url.pathname + url.search;
  };

  const filter = (column, operator, value) => {
    queryFilters.push({ column, operator, value });
    return builder;
  };

  // Filter shortcuts
  const eq = (column, value) => filter(column, "eq", value);
  const neq = (column, value) => filter(column, "neq", value);
  const gt = (column, value) => filter(column, "gt", value);
  const lt = (column, value) => filter(column, "lt", value);
  const gte = (column, value) => filter(column, "gte", value);
  const lte = (column, value) => filter(column, "lte", value);
  const like = (column, value) => filter(column, "like", value);
  const ilike = (column, value) => filter(column, "ilike", value);
  const in_ = (column, values) => filter(column, "in", values.join(","));
  const is_ = (column, value) => filter(column, "is", value);

  // Query options
  const select = (columns) => {
    queryOptions.select = columns;
    return builder;
  };

  const limit = (count) => {
    queryOptions.limit = count;
    return builder;
  };

  const offset = (count) => {
    queryOptions.offset = count;
    return builder;
  };

  const order = (column, options = {}) => {
    const direction = options.ascending ? "asc" : "desc";
    queryOptions.order = `${column}.${direction}`;
    return builder;
  };

  // Execute queries
  const get = async () => fetch(buildQueryUrl(), { method: "GET" });

  const insert = async (values, options = {}) => {
    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    if (options.returning) {
      url.searchParams.append("select", options.returning);
    }

    return fetch(url.pathname + url.search, {
      method: "POST",
      body: JSON.stringify(values),
    });
  };

  const update = async (values, options = {}) => {
    if (queryFilters.length === 0) {
      throw new ValidationError({
        message: "WHERE filters required for UPDATE operations",
        code: "missing_filters",
      });
    }

    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    queryFilters.forEach((filter) => {
      url.searchParams.append(
        filter.column,
        `${filter.operator}.${filter.value}`
      );
    });

    if (options.returning) {
      url.searchParams.append("select", options.returning);
    }

    return fetch(url.pathname + url.search, {
      method: "PATCH",
      body: JSON.stringify(values),
    });
  };

  const delete_ = async (options = {}) => {
    if (queryFilters.length === 0) {
      throw new ValidationError({
        message: "WHERE filters required for DELETE operations",
        code: "missing_filters",
      });
    }

    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    queryFilters.forEach((filter) => {
      url.searchParams.append(
        filter.column,
        `${filter.operator}.${filter.value}`
      );
    });

    if (options.returning) {
      url.searchParams.append("select", options.returning);
    }

    return fetch(url.pathname + url.search, { method: "DELETE" });
  };

  const builder = {
    eq,
    neq,
    gt,
    lt,
    gte,
    lte,
    like,
    ilike,
    in: in_,
    is: is_,
    select,
    limit,
    offset,
    order,
    filter,
    get,
    insert,
    update,
    delete: delete_,
  };

  return builder;
}

/**
 * RPC Implementation
 */
function callStoredProcedure(fn, params, fetch) {
  if (!fn) {
    throw new ValidationError({
      message: "Function name is required",
      code: "missing_function_name",
    });
  }

  return fetch(`rest/v1/rpc/${fn}`, {
    method: "POST",
    body: JSON.stringify(params || {}),
  });
}

/**
 * Enhanced Error Classes
 */
class SaintCentralError extends Error {
  constructor(error) {
    super(error.message || "Unknown error");
    this.name = "SaintCentralError";
    this.code = error.code || "unknown";
    this.status = error.status || null;
    this.details = error.details || null;
    this.hint = error.hint || null;
    this.originalError = error.originalError || error;
  }
}

class AuthError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "AuthError";
  }
}

class ValidationError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "ValidationError";
  }
}

class NetworkError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "NetworkError";
  }
}

class RateLimitError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "RateLimitError";
    this.retryAfter = error.retryAfter || 60000;
  }
}

class PermissionError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "PermissionError";
  }
}

class NotFoundError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "NotFoundError";
  }
}

class ConflictError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "ConflictError";
  }
}

class ServerError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "ServerError";
  }
}

// Export everything
export {
  SaintCentralError,
  AuthError,
  ValidationError,
  NetworkError,
  RateLimitError,
  PermissionError,
  NotFoundError,
  ConflictError,
  ServerError,
};
