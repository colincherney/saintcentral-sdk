/**
 * Saint Central SDK - Secure Auth Client
 * Mandatory encryption for all auth operations
 * @version 3.0.0
 */

import { SaintCentralAuthError } from "./client.js";

export class AuthClient {
  constructor(client) {
    this.client = client;
    this.config = client.config;
    const managers = client._getManagers();
    this.storage = managers.storage;
    this.encryption = managers.encryption;
    this.requestManager = managers.requestManager;

    this.AUTH_KEY = "saint_central_auth";
    this.REFRESH_THRESHOLD = 5 * 60 * 1000; // 5 minutes
  }

  async signUp(credentials) {
    try {
      this._validateCredentials(credentials, true);

      const encryptedPayload = await this._encryptAuthPayload({
        email: credentials.email.toLowerCase().trim(),
        password: credentials.password,
        metadata: credentials.metadata || {},
      });

      const response = await this.requestManager.request("auth/signup", {
        method: "POST",
        body: encryptedPayload,
        headers: { "Content-Type": "application/encrypted+json" },
      });

      if (response.session || response.access_token) {
        await this._storeSession(response.session || response);
        this.client._emitAuthStateChange(
          "SIGNED_IN",
          response.session || response
        );
      }

      return { data: response, error: null };
    } catch (error) {
      return this._handleAuthError(error, "SIGNUP_ERROR");
    }
  }

  async signIn(credentials) {
    return this.signInWithPassword(credentials);
  }

  async signInWithPassword(credentials) {
    try {
      this._validateCredentials(credentials);

      const encryptedPayload = await this._encryptAuthPayload({
        email: credentials.email.toLowerCase().trim(),
        password: credentials.password,
      });

      const response = await this.requestManager.request("auth/signin", {
        method: "POST",
        body: encryptedPayload,
        headers: { "Content-Type": "application/encrypted+json" },
      });

      if (response.session || response.access_token) {
        await this._storeSession(response.session || response);
        this.client._emitAuthStateChange(
          "SIGNED_IN",
          response.session || response
        );
      }

      return { data: response, error: null };
    } catch (error) {
      return this._handleAuthError(error, "SIGNIN_ERROR");
    }
  }

  async signOut() {
    try {
      const session = await this._getStoredSession();

      if (session?.access_token) {
        try {
          await this.requestManager.request("auth/signout", {
            method: "POST",
            headers: { Authorization: `Bearer ${session.access_token}` },
          });
        } catch (error) {
          if (this.config.debug) {
            console.warn(
              "Saint Central SDK: Server signout failed:",
              error.message
            );
          }
        }
      }

      await this._clearSession();
      this.client._emitAuthStateChange("SIGNED_OUT", null);

      return { data: null, error: null };
    } catch (error) {
      return this._handleAuthError(error, "SIGNOUT_ERROR");
    }
  }

  async getSession() {
    try {
      const session = await this._getStoredSession();

      if (!session) {
        return { data: { session: null }, error: null };
      }

      if (this._isTokenExpired(session)) {
        if (session.refresh_token) {
          const refreshResult = await this.refreshSession(
            session.refresh_token
          );
          if (refreshResult.data?.session) {
            return {
              data: { session: refreshResult.data.session },
              error: null,
            };
          }
        }

        await this._clearSession();
        return { data: { session: null }, error: null };
      }

      if (this._shouldRefreshToken(session) && session.refresh_token) {
        this.refreshSession(session.refresh_token).catch((error) => {
          if (this.config.debug) {
            console.warn(
              "Saint Central SDK: Auto-refresh failed:",
              error.message
            );
          }
        });
      }

      return { data: { session }, error: null };
    } catch (error) {
      return this._handleAuthError(error, "SESSION_ERROR");
    }
  }

  async refreshSession(refreshToken) {
    try {
      const token =
        refreshToken || (await this._getStoredSession())?.refresh_token;

      if (!token) {
        throw new SaintCentralAuthError(
          "No refresh token available",
          "NO_REFRESH_TOKEN"
        );
      }

      const response = await this.requestManager.request("auth/token", {
        method: "POST",
        body: { refresh_token: token },
      });

      if (response.session || response.access_token) {
        const newSession = response.session || response;
        await this._storeSession(newSession);
        this.client._emitAuthStateChange("TOKEN_REFRESHED", newSession);
        return { data: { session: newSession }, error: null };
      }

      throw new SaintCentralAuthError(
        "Invalid refresh response",
        "REFRESH_FAILED"
      );
    } catch (error) {
      await this._clearSession();
      this.client._emitAuthStateChange("SIGNED_OUT", null);
      return this._handleAuthError(error, "REFRESH_ERROR");
    }
  }

  async resetPassword(email) {
    try {
      if (!email || !this._isValidEmail(email)) {
        throw new SaintCentralAuthError(
          "Valid email required",
          "INVALID_EMAIL"
        );
      }

      const encryptedPayload = await this._encryptAuthPayload({
        email: email.toLowerCase().trim(),
      });

      const response = await this.requestManager.request("auth/recover", {
        method: "POST",
        body: encryptedPayload,
        headers: { "Content-Type": "application/encrypted+json" },
      });

      this.client._emitAuthStateChange("PASSWORD_RECOVERY", null);

      return { data: response, error: null };
    } catch (error) {
      return this._handleAuthError(error, "RESET_PASSWORD_ERROR");
    }
  }

  // Private methods
  _validateCredentials(credentials, isSignUp = false) {
    if (!credentials || typeof credentials !== "object") {
      throw new SaintCentralAuthError(
        "Credentials object required",
        "INVALID_CREDENTIALS"
      );
    }

    if (!credentials.email || !this._isValidEmail(credentials.email)) {
      throw new SaintCentralAuthError("Valid email required", "INVALID_EMAIL");
    }

    if (!credentials.password) {
      throw new SaintCentralAuthError("Password required", "MISSING_PASSWORD");
    }

    if (isSignUp && credentials.password.length < 8) {
      throw new SaintCentralAuthError(
        "Password must be at least 8 characters",
        "WEAK_PASSWORD"
      );
    }
  }

  _isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  async _encryptAuthPayload(payload) {
    try {
      await this.encryption.ensureSession();
      const encrypted = await this.encryption.encrypt(payload);

      if (!encrypted.encrypted) {
        throw new Error("Encryption failed - payload not encrypted");
      }

      return encrypted;
    } catch (error) {
      throw new SaintCentralAuthError(
        `Auth encryption failed: ${error.message}`,
        "ENCRYPTION_FAILED",
        { originalError: error.message }
      );
    }
  }

  async _storeSession(session) {
    try {
      const sessionData = {
        ...session,
        stored_at: Date.now(),
      };

      await this.storage.setItem(this.AUTH_KEY, JSON.stringify(sessionData));
    } catch (error) {
      if (this.config.debug) {
        console.warn(
          "Saint Central SDK: Failed to store session:",
          error.message
        );
      }
    }
  }

  async _getStoredSession() {
    try {
      const stored = await this.storage.getItem(this.AUTH_KEY);
      if (!stored) return null;
      return JSON.parse(stored);
    } catch (error) {
      if (this.config.debug) {
        console.warn(
          "Saint Central SDK: Failed to retrieve session:",
          error.message
        );
      }
      return null;
    }
  }

  async _clearSession() {
    try {
      await this.storage.removeItem(this.AUTH_KEY);
      await this.storage.removeItem("saint_central_session");
    } catch (error) {
      if (this.config.debug) {
        console.warn(
          "Saint Central SDK: Failed to clear session:",
          error.message
        );
      }
    }
  }

  _isTokenExpired(session) {
    if (!session.expires_at) return false;
    return Date.now() / 1000 > session.expires_at;
  }

  _shouldRefreshToken(session) {
    if (!session.expires_at) return false;
    const timeUntilExpiry = session.expires_at * 1000 - Date.now();
    return timeUntilExpiry < this.REFRESH_THRESHOLD;
  }

  _handleAuthError(error, defaultCode) {
    const authError = new SaintCentralAuthError(
      error.message || "Authentication failed",
      error.code || defaultCode,
      error.details || null
    );

    if (this.config.debug) {
      console.error("Saint Central SDK Auth Error:", authError);
    }

    return { data: null, error: authError };
  }
}
