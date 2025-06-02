/**
 * Saint Central SDK - Simplified Version
 *
 * Focus: Auth + CRUD operations only
 * Simple, clean API with automatic security handling
 *
 * @version 2.1.0
 */

export function createClient(url, options = {}) {
  const apiUrl = new URL(url);
  const config = {
    timeout: 30000,
    retries: 2,
    ...options,
  };

  // Auth storage
  const AUTH_KEY = "saint_central_auth";
  const SESSION_KEY = "saint_central_session";

  // Simple storage helpers
  const getAuth = () => {
    try {
      const stored = localStorage.getItem(AUTH_KEY);
      if (!stored) return null;

      const auth = JSON.parse(stored);
      if (auth.expires_at && Date.now() / 1000 > auth.expires_at) {
        clearAuth();
        return null;
      }
      return auth;
    } catch {
      return null;
    }
  };

  const setAuth = (auth) => {
    try {
      localStorage.setItem(AUTH_KEY, JSON.stringify(auth));
    } catch {}
  };

  const clearAuth = () => {
    try {
      localStorage.removeItem(AUTH_KEY);
      localStorage.removeItem(SESSION_KEY);
    } catch {}
  };

  // Session management for encryption
  let sessionData = null;

  const initSession = async () => {
    if (sessionData) return sessionData;

    try {
      // Check for stored session
      const stored = localStorage.getItem(SESSION_KEY);
      if (stored) {
        const session = JSON.parse(stored);
        if (session.expiresAt && Date.now() < session.expiresAt) {
          sessionData = session;
          return sessionData;
        }
      }

      // Create new session
      const response = await fetch(`${apiUrl.origin}/auth/key-exchange`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          clientInfo: {
            timestamp: Date.now(),
            version: "2.1.0",
          },
        }),
      });

      if (!response.ok) throw new Error("Session initialization failed");

      const result = await response.json();
      sessionData = result.data;

      try {
        localStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
      } catch {}

      return sessionData;
    } catch (error) {
      console.warn("Session init failed, using unencrypted mode:", error);
      return null;
    }
  };

  // Simple encryption (only if session available)
  const encrypt = async (data) => {
    if (!sessionData?.sessionKey) return data;

    try {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(JSON.stringify(data));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const keyBuffer = new Uint8Array(
        sessionData.sessionKey
          .match(/.{1,2}/g)
          .map((byte) => parseInt(byte, 16))
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

      return {
        version: 2,
        algorithm: "aes-256-gcm",
        data: btoa(String.fromCharCode(...result)),
        encrypted: true,
      };
    } catch {
      return data; // Fallback to unencrypted
    }
  };

  // HTTP request helper
  const request = async (path, options = {}) => {
    const auth = getAuth();
    const headers = {
      "Content-Type": "application/json",
      ...options.headers,
    };

    // Always init session for auth operations
    const isAuthOperation = path.startsWith("auth/");
    if (isAuthOperation) {
      await initSession();
    }

    if (sessionData?.sessionId) {
      headers["X-Session-ID"] = sessionData.sessionId;
    }

    if (auth?.access_token) {
      headers["Authorization"] = `Bearer ${auth.access_token}`;
    }

    let body = options.body;
    if (body && typeof body === "object") {
      // ALWAYS encrypt auth operations
      if (isAuthOperation) {
        if (!sessionData?.sessionKey) {
          throw new Error("Encryption required for auth operations");
        }
        try {
          body = await encrypt(body);
          headers["Content-Type"] = "application/encrypted+json";
        } catch (error) {
          throw new Error("Failed to encrypt auth request: " + error.message);
        }
      }
      body = JSON.stringify(body);
    }

    const response = await fetch(`${apiUrl.origin}/${path}`, {
      method: options.method || "GET",
      headers,
      body,
      signal: AbortSignal.timeout(config.timeout),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error?.message || `HTTP ${response.status}`);
    }

    const result = await response.json();
    return result.data || result;
  };

  // Auth API
  const auth = {
    async signUp(email, password, metadata = {}) {
      const result = await request("auth/signup", {
        method: "POST",
        body: { email, password, metadata },
      });

      if (result.session || result.access_token) {
        setAuth(result.session || result);
      }

      return { data: result, error: null };
    },

    async signIn(email, password) {
      const result = await request("auth/signin", {
        method: "POST",
        body: { email, password },
      });

      if (result.session || result.access_token) {
        setAuth(result.session || result);
      }

      return { data: result, error: null };
    },

    async signOut() {
      try {
        await request("auth/signout", { method: "POST" });
      } catch {}

      clearAuth();
      sessionData = null;

      return { error: null };
    },

    async getSession() {
      const auth = getAuth();
      return {
        data: { session: auth },
        error: null,
      };
    },

    async resetPassword(email) {
      const result = await request("auth/recover", {
        method: "POST",
        body: { email },
      });

      return { data: result, error: null };
    },
  };

  // Database API
  const from = (table) => {
    const buildQuery = (filters = {}, options = {}) => {
      const params = new URLSearchParams();

      // Add filters
      Object.entries(filters).forEach(([key, value]) => {
        if (typeof value === "object" && value.operator) {
          params.append(key, `${value.operator}.${value.value}`);
        } else {
          params.append(key, `eq.${value}`);
        }
      });

      // Add options
      if (options.select) params.append("select", options.select);
      if (options.order) params.append("order", options.order);
      if (options.limit) params.append("limit", options.limit);
      if (options.offset) params.append("offset", options.offset);

      return params.toString();
    };

    return {
      // Select data
      async select(columns = "*") {
        const query = buildQuery({}, { select: columns });
        const path = `rest/v1/${table}${query ? "?" + query : ""}`;
        return request(path);
      },

      // Find with filters
      async find(filters = {}, options = {}) {
        const query = buildQuery(filters, options);
        const path = `rest/v1/${table}${query ? "?" + query : ""}`;
        return request(path);
      },

      // Find one record
      async findOne(filters = {}) {
        const results = await this.find(filters, { limit: 1 });
        return results[0] || null;
      },

      // Insert data
      async insert(data) {
        return request(`rest/v1/${table}`, {
          method: "POST",
          body: data,
        });
      },

      // Update data
      async update(filters, data) {
        if (Object.keys(filters).length === 0) {
          throw new Error("Filters required for update");
        }

        const query = buildQuery(filters);
        const path = `rest/v1/${table}${query ? "?" + query : ""}`;

        return request(path, {
          method: "PATCH",
          body: data,
        });
      },

      // Delete data
      async delete(filters) {
        if (Object.keys(filters).length === 0) {
          throw new Error("Filters required for delete");
        }

        const query = buildQuery(filters);
        const path = `rest/v1/${table}${query ? "?" + query : ""}`;

        return request(path, { method: "DELETE" });
      },

      // Chainable query builder for complex queries
      eq(column, value) {
        return this._addFilter(column, "eq", value);
      },

      neq(column, value) {
        return this._addFilter(column, "neq", value);
      },

      gt(column, value) {
        return this._addFilter(column, "gt", value);
      },

      lt(column, value) {
        return this._addFilter(column, "lt", value);
      },

      gte(column, value) {
        return this._addFilter(column, "gte", value);
      },

      lte(column, value) {
        return this._addFilter(column, "lte", value);
      },

      like(column, value) {
        return this._addFilter(column, "like", value);
      },

      in(column, values) {
        return this._addFilter(column, "in", values.join(","));
      },

      order(column, direction = "asc") {
        this._queryOptions.order = `${column}.${direction}`;
        return this;
      },

      limit(count) {
        this._queryOptions.limit = count;
        return this;
      },

      offset(count) {
        this._queryOptions.offset = count;
        return this;
      },

      async get() {
        const query = buildQuery(this._filters || {}, this._queryOptions || {});
        const path = `rest/v1/${table}${query ? "?" + query : ""}`;
        return request(path);
      },

      _addFilter(column, operator, value) {
        this._filters = this._filters || {};
        this._filters[column] = { operator, value };
        return this;
      },

      _filters: {},
      _queryOptions: {},
    };
  };

  // RPC function calls
  const rpc = async (functionName, params = {}) => {
    return request(`rest/v1/rpc/${functionName}`, {
      method: "POST",
      body: params,
    });
  };

  return {
    auth,
    from,
    rpc,

    // Direct methods for common operations
    async getUser() {
      const session = await auth.getSession();
      return session.data.session?.user || null;
    },

    async isAuthenticated() {
      const session = await auth.getSession();
      return !!session.data.session?.access_token;
    },
  };
}

// Simple error wrapper for better error handling
export const createClientWithErrorHandling = (url, options = {}) => {
  const client = createClient(url, options);

  // Wrap methods to handle errors gracefully
  const wrapWithErrorHandling = (obj) => {
    return new Proxy(obj, {
      get(target, prop) {
        const value = target[prop];

        if (typeof value === "function") {
          return async (...args) => {
            try {
              return await value.apply(target, args);
            } catch (error) {
              console.error(`Saint Central ${prop} error:`, error);
              return { data: null, error: error.message };
            }
          };
        }

        if (typeof value === "object" && value !== null) {
          return wrapWithErrorHandling(value);
        }

        return value;
      },
    });
  };

  return wrapWithErrorHandling(client);
};
