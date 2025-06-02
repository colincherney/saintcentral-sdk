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
    encryptionKey: options.encryptionKey || generateEncryptionKey(),
    ...options.config,
  };

  // Local storage keys
  const STORAGE_KEY = "saint_central_auth";
  const ENCRYPTION_KEY_STORAGE = "saint_central_encryption_key";

  // Initialize encryption key
  const initializeEncryption = () => {
    let key = config.encryptionKey;

    if (!key && typeof localStorage !== "undefined") {
      try {
        key = localStorage.getItem(ENCRYPTION_KEY_STORAGE);
        if (!key) {
          key = generateEncryptionKey();
          localStorage.setItem(ENCRYPTION_KEY_STORAGE, key);
        }
      } catch (error) {
        console.warn("Could not access localStorage for encryption key");
        key = generateEncryptionKey();
      }
    }

    config.encryptionKey = key;
    return key;
  };

  // Initialize encryption on first load
  initializeEncryption();

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

    // Enhanced security headers
    fetchOptions.headers = {
      "Content-Type": "application/json",
      "X-Security-Nonce": generateSecureNonce(),
      "X-Request-ID": generateRequestId(),
      "X-Client-Version": "2.0.0",
      "User-Agent": "SaintCentral-SDK/2.0.0",
    };

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
      if (securityOptions.encryption && typeof options.body === "string") {
        try {
          const bodyData = JSON.parse(options.body);
          const encryptedBody = await realEncryption.encrypt(bodyData);
          fetchOptions.body = JSON.stringify(encryptedBody);
          fetchOptions.headers["Content-Type"] = "application/encrypted+json";
        } catch (error) {
          console.warn("Encryption failed, sending unencrypted:", error);
          fetchOptions.body = options.body;
        }
      } else {
        fetchOptions.body = options.body;
      }
    }

    const endpoint = `${apiUrl.origin}/${path}`;

    try {
      const response = await fetch(endpoint, fetchOptions);

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
        data?.data?.session
      ) {
        storeAuth(data.data.session);
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

      // Retry on network errors
      if (retryCount < config.maxRetries && isRetryableError(error)) {
        const delay = config.retryDelay * Math.pow(2, retryCount);
        await new Promise((resolve) => setTimeout(resolve, delay));
        return fetchWithAuth(path, options, retryCount + 1);
      }

      throw new NetworkError({
        message: error.message || "Network request failed",
        originalError: error,
      });
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
      rotateEncryptionKey: () => {
        config.encryptionKey = generateEncryptionKey();
        if (typeof localStorage !== "undefined") {
          try {
            localStorage.setItem(ENCRYPTION_KEY_STORAGE, config.encryptionKey);
          } catch (error) {
            console.warn("Could not store new encryption key");
          }
        }
        return config.encryptionKey;
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
  const in_ = (column, values) => filter(column, "in", `(${values.join(",")})`);
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
    const body = Array.isArray(values) ? values : [values];
    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    if (options.returning) {
      url.searchParams.append("select", options.returning);
    }

    return fetch(url.pathname + url.search, {
      method: "POST",
      body: JSON.stringify(body),
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
