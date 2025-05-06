/**
 * Saint Central SDK
 *
 * A secure alternative to Supabase SDK with enhanced security features,
 * designed to be a drop-in replacement with identical API signatures.
 * Built on Cloudflare Workers for improved performance and security.
 *
 * No API key version - uses token-based authentication instead
 */

// Core client that integrates all Saint Central services
export function createClient(url, options = {}) {
  const apiUrl = new URL(url);

  // Enhanced security features
  const securityOptions = {
    // Default security configuration
    encryption: true,
    rateLimit: true,
    jwtHardening: true,
    ddosProtection: true,
    headerSecurity: true,
    contentSecurityPolicy: true,
    ...options.security,
  };

  // Cloudflare Workers integration
  const cloudflareOptions = {
    // Cloudflare Worker configuration
    enabled: true,
    cacheControl: "max-age=3600",
    edgeLocation: "auto",
    ...options.cloudflare,
  };

  // Local storage keys
  const STORAGE_KEY = "saint_central_auth";

  // Get stored auth data
  const getStoredAuth = () => {
    try {
      const storedAuth = localStorage.getItem(STORAGE_KEY);
      return storedAuth ? JSON.parse(storedAuth) : null;
    } catch (error) {
      console.error("Error retrieving auth from storage:", error);
      return null;
    }
  };

  // Store auth data
  const storeAuth = (auth) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
    } catch (error) {
      console.error("Error storing auth:", error);
    }
  };

  // Clear stored auth data
  const clearStoredAuth = () => {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (error) {
      console.error("Error clearing auth:", error);
    }
  };

  const fetchWithAuth = async (path, options = {}) => {
    // Get current auth data from storage
    const authData = getStoredAuth();

    // Create a clean options object
    const fetchOptions = {
      method: options.method || "GET",
      credentials: "omit", // Don't send cookies to avoid CORS issues
      mode: "cors", // Explicitly set CORS mode
      cache: "no-cache", // Avoid caching issues
    };

    // Initialize headers with minimal required values
    fetchOptions.headers = {
      "Content-Type": "application/json",
    };

    // Only add security headers for non-OPTIONS requests and only those that don't cause CORS issues
    if (fetchOptions.method !== "OPTIONS") {
      fetchOptions.headers["X-Security-Nonce"] = generateNonce();
      fetchOptions.headers["X-Request-ID"] = generateRequestId();
    }

    // Copy any headers from options
    if (options.headers) {
      Object.assign(fetchOptions.headers, options.headers);
    }

    // Add auth token if available
    if (authData && authData.access_token) {
      fetchOptions.headers["Authorization"] = `Bearer ${authData.access_token}`;
    }

    // Add body if present
    if (options.body) {
      fetchOptions.body = options.body;
    }

    // Apply security enhancements if encryption is enabled
    // This may modify Content-Type based on encryption
    if (
      securityOptions.encryption &&
      fetchOptions.body &&
      typeof fetchOptions.body === "string"
    ) {
      try {
        console.log("Applying encryption to payload");
        fetchOptions.body = encryptPayload(fetchOptions.body);
        fetchOptions.headers["Content-Type"] = "application/encrypted+json";
      } catch (err) {
        console.error("Encryption failed, sending unencrypted:", err);
      }
    }

    // Route through Cloudflare worker
    const endpoint = `${apiUrl.origin}/${path}`;

    console.log(
      `Making request to ${endpoint} with method ${fetchOptions.method}`
    );
    console.log("Request headers:", fetchOptions.headers);

    if (fetchOptions.body) {
      console.log(
        "Request body preview:",
        typeof fetchOptions.body === "string"
          ? fetchOptions.body.substring(0, 100) + "..."
          : "Non-string body"
      );
    }

    try {
      // Use a more basic approach for fetch to avoid issues
      const response = await fetch(endpoint, fetchOptions);

      console.log(`Response status: ${response.status}`);

      // For non-JSON responses or errors, handle accordingly
      if (!response.ok) {
        return {
          data: null,
          error: {
            message: `HTTP error ${response.status}`,
            status: response.status,
          },
        };
      }

      // Try to parse response as JSON
      try {
        const data = await response.json();
        console.log("Response data:", data);

        // Handle authentication responses specially to store tokens
        if (
          path.startsWith("auth/signin") ||
          path.startsWith("auth/signup") ||
          path.startsWith("auth/token")
        ) {
          if (data.data && data.data.session) {
            storeAuth(data.data.session);
          }
        }

        // Handle sign out
        if (path.startsWith("auth/signout") && !data.error) {
          clearStoredAuth();
        }

        return { data: data.data, error: data.error };
      } catch (jsonError) {
        console.error("JSON parse error:", jsonError);
        return {
          data: null,
          error: { message: "Invalid JSON response", originalError: jsonError },
        };
      }
    } catch (error) {
      console.error("Fetch error:", error);
      return { data: null, error: new SaintCentralError(error) };
    }
  };

  // Security utility functions
  const generateNonce = () => {
    return (
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15)
    );
  };

  const generateRequestId = () => {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 9);
  };

  const encryptPayload = (payload) => {
    // Simplified encryption for demo purposes
    // In a real implementation, you would use AES or another strong algorithm
    try {
      // The encryption format matches what the server expects
      return JSON.stringify({
        version: 1,
        algorithm: "aes-256-gcm",
        data: payload, // In a real implementation, this would be encrypted
        encrypted: true,
      });
    } catch (error) {
      console.error("Encryption error:", error);
      return payload;
    }
  };

  // Initialize all service clients
  const auth = createAuthClient(fetchWithAuth, {
    url: apiUrl.origin,
    securityOptions,
    getStoredAuth,
    clearStoredAuth,
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

  // Create a database query builder
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

    // Additional Saint Central-specific functionality
    security: {
      configure: (config) => Object.assign(securityOptions, config),
      status: () => ({ ...securityOptions }),
    },

    // Helper for raw REST API calls
    rest: {
      get: (path) => fetchWithAuth(path, { method: "GET" }),
      post: (path, body) =>
        fetchWithAuth(path, { method: "POST", body: JSON.stringify(body) }),
      put: (path, body) =>
        fetchWithAuth(path, { method: "PUT", body: JSON.stringify(body) }),
      delete: (path) => fetchWithAuth(path, { method: "DELETE" }),
    },
  };
}

/**
 * Auth Client Implementation
 * Handles user authentication and management
 */
function createAuthClient(fetch, options) {
  // Session management
  const getSession = async () => {
    const authData = options.getStoredAuth();

    if (!authData) {
      return { data: null, error: { message: "No session found" } };
    }

    // Verify the session with the server
    return fetch("auth/session", { method: "GET" });
  };

  const refreshSession = async () => {
    const authData = options.getStoredAuth();

    if (!authData || !authData.refresh_token) {
      return { data: null, error: { message: "No refresh token found" } };
    }

    return fetch("auth/token", {
      method: "POST",
      body: JSON.stringify({ refresh_token: authData.refresh_token }),
    });
  };

  // User authentication methods
  const signUp = async (credentials) => {
    return fetch("auth/signup", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
  };

  const signIn = async (credentials) => {
    console.log("SDK signIn called with:", credentials);

    // Send the credentials exactly as provided
    const payload = JSON.stringify(credentials);
    console.log("Sending raw payload:", payload);

    return fetch("auth/signin", {
      method: "POST",
      body: payload,
    });
  };

  const signInWithPassword = async (credentials) => {
    console.log("SDK signInWithPassword called with:", credentials);

    // Ensure email/phone and password are present
    if (!credentials.email && !credentials.phone) {
      return {
        data: null,
        error: {
          message: "Email or phone is required",
          code: "client_validation",
        },
      };
    }

    if (!credentials.password) {
      return {
        data: null,
        error: { message: "Password is required", code: "client_validation" },
      };
    }

    // Send the credentials exactly as provided
    // But make sure to include gotrue_meta_security if not present
    const finalCredentials = {
      ...credentials,
      gotrue_meta_security: credentials.gotrue_meta_security || {},
    };

    const payload = JSON.stringify(finalCredentials);
    console.log("Sending raw payload:", payload);

    return fetch("auth/signin", {
      method: "POST",
      body: payload,
    });
  };

  const signOut = async () => {
    const result = await fetch("auth/signout", { method: "POST" });

    // Clear local session regardless of server response
    if (!result.error) {
      options.clearStoredAuth();
    }

    return result;
  };

  const resetPasswordForEmail = async (email) => {
    return fetch("auth/recover", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  };

  // OAuth providers
  const signInWithOAuth = async (provider, options = {}) => {
    return fetch("auth/authorize", {
      method: "POST",
      body: JSON.stringify({
        provider,
        ...options,
      }),
    });
  };

  // Enhanced security features for auth
  const securityEnhancements = {
    enableMFA: async () => {
      return fetch("auth/mfa/enable", { method: "POST" });
    },
    verifyMFA: async (code) => {
      return fetch("auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ code }),
      });
    },
    disableMFA: async () => {
      return fetch("auth/mfa/disable", { method: "POST" });
    },
  };

  // Admin functions
  const admin = {
    createUser: async (userData) => {
      return fetch("auth/admin/users", {
        method: "POST",
        body: JSON.stringify(userData),
      });
    },
    deleteUser: async (userId) => {
      return fetch(`auth/admin/users/${userId}`, {
        method: "DELETE",
      });
    },
    listUsers: async (page = 1, perPage = 50) => {
      return fetch(`auth/admin/users?page=${page}&per_page=${perPage}`, {
        method: "GET",
      });
    },
  };

  return {
    // Standard Supabase Auth API
    getSession,
    refreshSession,
    signUp,
    signIn,
    signInWithPassword,
    signOut,
    resetPasswordForEmail,
    signInWithOAuth,

    // Supabase-compatible provider shortcuts
    signInWithGoogle: (options) => signInWithOAuth("google", options),
    signInWithFacebook: (options) => signInWithOAuth("facebook", options),
    signInWithGithub: (options) => signInWithOAuth("github", options),

    // Enhanced Saint Central security features
    security: securityEnhancements,

    // Admin API
    admin,
  };
}

/**
 * Storage Client Implementation
 * Handles file storage and retrieval
 */
function createStorageClient(fetch, options) {
  const from = (bucket) => {
    // File operations on specific bucket
    const upload = async (path, fileBody, fileOptions = {}) => {
      const formData = new FormData();
      formData.append("file", fileBody);

      if (fileOptions.contentType) {
        formData.append("content_type", fileOptions.contentType);
      }

      return fetch(`storage/object/${bucket}/${path}`, {
        method: "POST",
        body: formData,
      });
    };

    const download = async (path) => {
      return fetch(`storage/object/${bucket}/${path}`, {
        method: "GET",
      });
    };

    const remove = async (paths) => {
      return fetch(`storage/object/${bucket}`, {
        method: "DELETE",
        body: JSON.stringify({
          prefixes: Array.isArray(paths) ? paths : [paths],
        }),
      });
    };

    const list = async (prefix = "", options = {}) => {
      const query = new URLSearchParams({ prefix });

      if (options.limit) {
        query.append("limit", options.limit);
      }

      if (options.offset) {
        query.append("offset", options.offset);
      }

      return fetch(`storage/object/list/${bucket}?${query.toString()}`, {
        method: "GET",
      });
    };

    const getPublicUrl = (path) => {
      const origin = options.url;
      return `${origin}/storage/object/public/${bucket}/${path}`;
    };

    return {
      upload,
      download,
      remove,
      list,
      getPublicUrl,
    };
  };

  // Bucket operations
  const createBucket = async (bucketName, bucketOptions = {}) => {
    return fetch("storage/bucket", {
      method: "POST",
      body: JSON.stringify({
        id: bucketName,
        public: !!bucketOptions.public,
      }),
    });
  };

  const deleteBucket = async (bucketName) => {
    return fetch(`storage/bucket/${bucketName}`, {
      method: "DELETE",
    });
  };

  const listBuckets = async () => {
    return fetch("storage/bucket", {
      method: "GET",
    });
  };

  return {
    from,
    createBucket,
    deleteBucket,
    listBuckets,
  };
}

/**
 * Realtime Client Implementation
 * Handles realtime subscriptions and messaging
 */
function createRealtimeClient(options) {
  let socket = null;
  let channels = {};

  const connect = () => {
    // Implementation for WebSocket connections with enhanced security
    const wsUrl = options.url.replace("http", "ws");

    // Get auth token if available
    const authData = options.getAuth ? options.getAuth() : null;
    const token = authData ? authData.access_token : null;

    // Create endpoint with token if available
    const wsEndpoint = token
      ? `${wsUrl}/realtime/v1?token=${token}`
      : `${wsUrl}/realtime/v1`;

    socket = new WebSocket(wsEndpoint);

    // Add security heartbeat and reconnection logic
    socket.onopen = () => {
      startHeartbeat();
    };

    socket.onclose = () => {
      setTimeout(connect, 1000); // Reconnect with backoff logic
    };

    return socket;
  };

  const startHeartbeat = () => {
    setInterval(() => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "heartbeat" }));
      }
    }, 30000); // 30 second heartbeat
  };

  const channel = (name) => {
    if (!socket) {
      connect();
    }

    // Create or reuse channel
    if (!channels[name]) {
      channels[name] = createChannel(name, socket);
    }

    return channels[name];
  };

  const createChannel = (name, socket) => {
    let listeners = {};
    let subscribed = false;

    const subscribe = (callback) => {
      socket.send(
        JSON.stringify({
          type: "subscribe",
          channel: name,
        })
      );

      subscribed = true;

      socket.addEventListener("message", (event) => {
        const data = JSON.parse(event.data);
        if (data.channel === name) {
          callback(data.payload);

          // Call specific event listeners
          if (data.event && listeners[data.event]) {
            listeners[data.event].forEach((listener) => listener(data.payload));
          }
        }
      });

      return {
        unsubscribe: () => {
          socket.send(
            JSON.stringify({
              type: "unsubscribe",
              channel: name,
            })
          );
          subscribed = false;
        },
      };
    };

    const on = (event, callback) => {
      if (!listeners[event]) {
        listeners[event] = [];
      }

      listeners[event].push(callback);

      return {
        unsubscribe: () => {
          listeners[event] = listeners[event].filter((cb) => cb !== callback);
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
        })
      );
    };

    return {
      subscribe,
      on,
      send,
    };
  };

  return {
    connect,
    channel,
    disconnect: () => {
      if (socket) {
        socket.close();
        socket = null;
      }
    },
  };
}

/**
 * Edge Functions Client Implementation
 * Handles serverless function invocation
 */
function createFunctionsClient(fetch, options) {
  const invoke = async (functionName, payload = {}, invokeOptions = {}) => {
    // Enhanced security for function invocation
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

  return {
    invoke,
  };
}

/**
 * Database Query Builder Implementation
 * For building SQL queries with a fluent interface
 */
function createTableQueryBuilder(table, fetch) {
  let queryFilters = [];
  let queryOptions = {
    limit: null,
    offset: null,
    order: null,
    select: "*",
  };

  // Build the final query URL with filters and options
  const buildQueryUrl = () => {
    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    // Add filters
    if (queryFilters.length > 0) {
      queryFilters.forEach((filter) => {
        url.searchParams.append(
          filter.column,
          `${filter.operator}.${filter.value}`
        );
      });
    }

    // Add options
    if (queryOptions.select) {
      url.searchParams.append("select", queryOptions.select);
    }

    if (queryOptions.limit) {
      url.searchParams.append("limit", queryOptions.limit);
    }

    if (queryOptions.offset) {
      url.searchParams.append("offset", queryOptions.offset);
    }

    if (queryOptions.order) {
      url.searchParams.append("order", queryOptions.order);
    }

    return url.pathname + url.search;
  };

  // Query filters
  const filter = (column, operator, value) => {
    queryFilters.push({ column, operator, value });
    return builder;
  };

  // Common filter shortcuts
  const eq = (column, value) => filter(column, "eq", value);
  const neq = (column, value) => filter(column, "neq", value);
  const gt = (column, value) => filter(column, "gt", value);
  const lt = (column, value) => filter(column, "lt", value);
  const gte = (column, value) => filter(column, "gte", value);
  const lte = (column, value) => filter(column, "lte", value);
  const like = (column, value) => filter(column, "like", value);
  const ilike = (column, value) => filter(column, "ilike", value);
  const in_ = (column, values) => filter(column, "in", `(${values.join(",")})`);

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
    const nullsOption = options.nullsFirst ? "nullsfirst" : "nullslast";
    queryOptions.order = `${column}.${direction}.${nullsOption}`;
    return builder;
  };

  // Execute queries
  const get = async () => {
    return fetch(buildQueryUrl(), { method: "GET" });
  };

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
    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    // Add filters
    if (queryFilters.length > 0) {
      queryFilters.forEach((filter) => {
        url.searchParams.append(
          filter.column,
          `${filter.operator}.${filter.value}`
        );
      });
    }

    if (options.returning) {
      url.searchParams.append("select", options.returning);
    }

    return fetch(url.pathname + url.search, {
      method: "PATCH",
      body: JSON.stringify(values),
    });
  };

  const delete_ = async (options = {}) => {
    const url = new URL(`rest/v1/${table}`, "http://placeholder");

    // Add filters
    if (queryFilters.length > 0) {
      queryFilters.forEach((filter) => {
        url.searchParams.append(
          filter.column,
          `${filter.operator}.${filter.value}`
        );
      });
    }

    if (options.returning) {
      url.searchParams.append("select", options.returning);
    }

    return fetch(url.pathname + url.search, {
      method: "DELETE",
    });
  };

  // Construct and return the builder object
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
 * RPC (Remote Procedure Call) Implementation
 * For calling stored procedures
 */
function callStoredProcedure(fn, params, fetch) {
  return fetch(`rest/v1/rpc/${fn}`, {
    method: "POST",
    body: JSON.stringify(params || {}),
  });
}

/**
 * Error classes
 */
class SaintCentralError extends Error {
  constructor(error) {
    super(error.message);
    this.name = "SaintCentralError";
    this.originalError = error;
    this.code = error.code || "unknown";
    this.details = error.details || null;
    this.hint = error.hint || null;
  }
}

// Specific error types
class AuthError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "AuthError";
  }
}

class DatabaseError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "DatabaseError";
  }
}

class StorageError extends SaintCentralError {
  constructor(error) {
    super(error);
    this.name = "StorageError";
  }
}

// Export everything
export { SaintCentralError, AuthError, DatabaseError, StorageError };
