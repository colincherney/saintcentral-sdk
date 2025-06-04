/**
 * Saint Central SDK - Secure Database Client
 * Supabase-compatible API with optional .encrypt() chain
 * @version 3.0.0
 */

import { SaintCentralDatabaseError } from "./client.js";

export class DatabaseClient {
  constructor(client) {
    this.client = client;
    this.config = client.config;
    const managers = client._getManagers();
    this.requestManager = managers.requestManager;
    this.encryption = managers.encryption;
  }

  from(table) {
    return new QueryBuilder(table, this);
  }

  async rpc(functionName, params = {}) {
    try {
      const response = await this.requestManager.request(
        `rest/v1/rpc/${functionName}`,
        {
          method: "POST",
          body: params,
        }
      );

      return { data: response, error: null };
    } catch (error) {
      return this._handleError(error, "RPC_ERROR");
    }
  }

  _handleError(error, defaultCode) {
    const dbError = new SaintCentralDatabaseError(
      error.message || "Database operation failed",
      error.code || defaultCode,
      error.details || null
    );

    if (this.config.debug) {
      console.error("Saint Central SDK Database Error:", dbError);
    }

    return { data: null, error: dbError };
  }
}

export class QueryBuilder {
  constructor(table, dbClient) {
    this.table = table;
    this.dbClient = dbClient;
    this.requestManager = dbClient.requestManager;
    this.encryption = dbClient.encryption;

    // Query state
    this._method = "GET";
    this._select = "*";
    this._filters = {};
    this._orderBy = null;
    this._limit = null;
    this._offset = null;
    this._body = null;
    this._shouldEncrypt = false;
    this._executed = false;
  }

  // Selection methods
  select(columns = "*") {
    this._select = columns;
    return this;
  }

  // Modification methods
  insert(values) {
    this._method = "POST";
    this._body = values;
    return this;
  }

  update(values) {
    this._method = "PATCH";
    this._body = values;
    return this;
  }

  upsert(values) {
    this._method = "POST";
    this._body = values;
    this._headers = { ...this._headers, Prefer: "resolution=merge-duplicates" };
    return this;
  }

  delete() {
    this._method = "DELETE";
    return this;
  }

  // Filter methods
  eq(column, value) {
    this._filters[column] = `eq.${value}`;
    return this;
  }

  neq(column, value) {
    this._filters[column] = `neq.${value}`;
    return this;
  }

  gt(column, value) {
    this._filters[column] = `gt.${value}`;
    return this;
  }

  gte(column, value) {
    this._filters[column] = `gte.${value}`;
    return this;
  }

  lt(column, value) {
    this._filters[column] = `lt.${value}`;
    return this;
  }

  lte(column, value) {
    this._filters[column] = `lte.${value}`;
    return this;
  }

  like(column, pattern) {
    this._filters[column] = `like.${pattern}`;
    return this;
  }

  ilike(column, pattern) {
    this._filters[column] = `ilike.${pattern}`;
    return this;
  }

  in(column, values) {
    const valueStr = Array.isArray(values) ? values.join(",") : values;
    this._filters[column] = `in.(${valueStr})`;
    return this;
  }

  is(column, value) {
    this._filters[column] = `is.${value}`;
    return this;
  }

  // Modifier methods
  order(column, options = {}) {
    const { ascending = true, nullsFirst = false } = options;
    const direction = ascending ? "asc" : "desc";
    const nulls = nullsFirst ? "nullsfirst" : "nullslast";
    this._orderBy = `${column}.${direction}.${nulls}`;
    return this;
  }

  limit(count) {
    this._limit = count;
    return this;
  }

  offset(count) {
    this._offset = count;
    return this;
  }

  range(from, to) {
    this._offset = from;
    this._limit = to - from + 1;
    return this;
  }

  // Encryption toggle - key feature for strong security
  encrypt() {
    this._shouldEncrypt = true;
    return this;
  }

  // Execution methods
  async then(onFulfilled, onRejected) {
    try {
      const result = await this._execute();
      return onFulfilled ? onFulfilled(result) : result;
    } catch (error) {
      return onRejected ? onRejected(error) : Promise.reject(error);
    }
  }

  async single() {
    const result = await this._execute();
    if (result.error) return result;

    const data = Array.isArray(result.data)
      ? result.data[0] || null
      : result.data;
    return { data, error: null };
  }

  async maybeSingle() {
    this.limit(2);
    const result = await this._execute();
    if (result.error) return result;

    if (Array.isArray(result.data)) {
      if (result.data.length === 0) {
        return { data: null, error: null };
      } else if (result.data.length === 1) {
        return { data: result.data[0], error: null };
      } else {
        return {
          data: null,
          error: new SaintCentralDatabaseError(
            "Multiple rows returned",
            "MULTIPLE_ROWS_ERROR"
          ),
        };
      }
    }

    return { data: result.data, error: null };
  }

  async _execute() {
    if (this._executed) {
      throw new SaintCentralDatabaseError(
        "Query already executed",
        "QUERY_ALREADY_EXECUTED"
      );
    }

    this._executed = true;

    try {
      const path = this._buildPath();
      const options = await this._buildRequestOptions();

      const response = await this.requestManager.request(path, options);

      return { data: response, error: null };
    } catch (error) {
      return this.dbClient._handleError(error, "QUERY_ERROR");
    }
  }

  _buildPath() {
    const params = new URLSearchParams();

    if (this._method === "GET" && this._select !== "*") {
      params.append("select", this._select);
    }

    Object.entries(this._filters).forEach(([key, value]) => {
      params.append(key, value);
    });

    if (this._orderBy) {
      params.append("order", this._orderBy);
    }

    if (this._limit !== null) {
      params.append("limit", this._limit);
    }
    if (this._offset !== null) {
      params.append("offset", this._offset);
    }

    const queryString = params.toString();
    return `rest/v1/${this.table}${queryString ? "?" + queryString : ""}`;
  }

  async _buildRequestOptions() {
    const options = {
      method: this._method,
      headers: this._headers || {},
    };

    if (this._body && ["POST", "PATCH", "PUT"].includes(this._method)) {
      if (this._shouldEncrypt) {
        try {
          await this.encryption.ensureSession();
          const encrypted = await this.encryption.encrypt(this._body);

          if (!encrypted.encrypted) {
            throw new Error("Encryption failed - payload not encrypted");
          }

          options.body = encrypted;
          options.headers["Content-Type"] = "application/encrypted+json";
        } catch (error) {
          throw new SaintCentralDatabaseError(
            `Database encryption failed: ${error.message}`,
            "ENCRYPTION_FAILED",
            { originalError: error.message }
          );
        }
      } else {
        options.body = this._body;
      }
    }

    return options;
  }

  // Additional utility methods
  count() {
    this._select = "count";
    return this;
  }

  not(column, operator, value) {
    this._filters[column] = `not.${operator}.${value}`;
    return this;
  }

  or(filters) {
    const orConditions = filters
      .map((filter) => {
        if (typeof filter === "string") return filter;
        return `${filter.column}.${filter.operator}.${filter.value}`;
      })
      .join(",");

    this._filters.or = `(${orConditions})`;
    return this;
  }

  textSearch(column, query, options = {}) {
    const { type = "plain", config = "english" } = options;
    let operator;

    switch (type) {
      case "plain":
        operator = "plfts";
        break;
      case "phrase":
        operator = "phfts";
        break;
      case "websearch":
        operator = "wfts";
        break;
      default:
        operator = "fts";
    }

    this._filters[column] = `${operator}(${config}).${query}`;
    return this;
  }
}
