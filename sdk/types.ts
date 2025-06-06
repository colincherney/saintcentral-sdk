/**
 * Saint Central SDK - Secure TypeScript Definitions
 * All database operations are automatically encrypted
 * @version 3.0.0
 */

// Core Configuration
export interface SaintCentralConfig {
  url: string;
  timeout?: number;
  retries?: number;
  enableEncryption?: boolean;
  encryptionLevel?: "strong"; // Only strong encryption supported
  storage?: "auto" | "memory" | "localStorage" | "asyncStorage";
  debug?: boolean;
  strongCryptoRequired?: true; // Always true
  authEncryptionRequired?: true; // Always true
}

// Response Types
export interface SaintCentralResponse<T = any> {
  data: T | null;
  error: SaintCentralError | null;
}

export interface SaintCentralError {
  message: string;
  code?: string;
  details?: any;
  hint?: string;
}

// Auth Types
export interface AuthUser {
  id: string;
  email: string;
  user_metadata?: Record<string, any>;
  app_metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
  email_confirmed_at?: string;
  last_sign_in_at?: string;
}

export interface AuthSession {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at: number;
  token_type: string;
  user: AuthUser;
}

export interface SignUpCredentials {
  email: string;
  password: string;
  metadata?: Record<string, any>;
}

export interface SignInCredentials {
  email: string;
  password: string;
}

export interface AuthResponse {
  data: {
    user: AuthUser | null;
    session: AuthSession | null;
  };
  error: SaintCentralError | null;
}

export type AuthChangeEvent =
  | "SIGNED_IN"
  | "SIGNED_OUT"
  | "TOKEN_REFRESHED"
  | "USER_UPDATED"
  | "PASSWORD_RECOVERY";

// Database Types
export type QueryOperator =
  | "eq"
  | "neq"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "like"
  | "ilike"
  | "in"
  | "is"
  | "not.is"
  | "cs"
  | "cd"
  | "sl"
  | "sr"
  | "nxl"
  | "nxr"
  | "adj"
  | "ov"
  | "fts"
  | "plfts"
  | "phfts"
  | "wfts";

export interface QueryBuilder<T = any> extends PromiseLike<SaintCentralResponse<T[]>> {
  select(columns?: string): QueryBuilder<T>;
  insert(values: Partial<T> | Partial<T>[]): QueryBuilder<T>;
  update(values: Partial<T>): QueryBuilder<T>;
  upsert(values: Partial<T> | Partial<T>[]): QueryBuilder<T>;
  delete(): QueryBuilder<T>;

  // Filters
  eq(column: keyof T, value: any): QueryBuilder<T>;
  neq(column: keyof T, value: any): QueryBuilder<T>;
  gt(column: keyof T, value: any): QueryBuilder<T>;
  gte(column: keyof T, value: any): QueryBuilder<T>;
  lt(column: keyof T, value: any): QueryBuilder<T>;
  lte(column: keyof T, value: any): QueryBuilder<T>;
  like(column: keyof T, value: string): QueryBuilder<T>;
  ilike(column: keyof T, value: string): QueryBuilder<T>;
  in(column: keyof T, values: any[]): QueryBuilder<T>;
  is(column: keyof T, value: null | boolean): QueryBuilder<T>;

  // Modifiers
  order(column: keyof T, options?: { ascending?: boolean; nullsFirst?: boolean }): QueryBuilder<T>;
  limit(count: number): QueryBuilder<T>;
  offset(count: number): QueryBuilder<T>;
  range(from: number, to: number): QueryBuilder<T>;

  // NOTE: .encrypt() method removed - all operations are automatically encrypted

  // Execution
  single(): Promise<SaintCentralResponse<T>>;
  maybeSingle(): Promise<SaintCentralResponse<T>>;
}

// Platform Types (Updated for security)
export interface PlatformInfo {
  isReactNative: boolean;
  isBrowser: boolean;
  isNode: boolean;
  hasAsyncStorage: boolean;
  hasLocalStorage: boolean;
  hasCrypto: boolean;
  hasSecureRandom: boolean;
  encryption: {
    available: boolean;
    method: string;
    level: "none" | "strong"; // Removed 'basic' - only strong encryption
    warning?: string;
  };
  authEncryptionEnabled: true; // Always true
}

// Encryption Types (Updated for new secure encryption module)
export interface EncryptedData {
  version: 2 | 3; // Added version 3 for new encryption module
  algorithm: "aes-256-gcm" | "aes-256-cbc"; // Only strong algorithms
  data: string;
  iv: string; // Required for version 3
  encrypted: true;
}

export interface EncryptionConfig {
  keySize: 256; // AES key size in bits
  ivSize: 96; // GCM IV size in bits (12 bytes)
  tagSize: 128; // GCM authentication tag size in bits (16 bytes)
}

export interface PlatformCrypto {
  type: "web-crypto" | "node-crypto" | "expo-crypto" | "unsupported";
  encrypt(data: string, key: Uint8Array): Promise<EncryptedData>;
  decrypt(encryptedData: EncryptedData, key: Uint8Array): Promise<string>;
  generateKey(): Promise<Uint8Array>;
  generateIV(): Uint8Array;
}

export interface EncryptionTestResult {
  success: boolean;
  platform: string;
  error?: string;
}

export interface PlatformCapabilities {
  type: string;
  capabilities: string[];
}

// Updated Secure Encryption Interface
export interface SecureEncryptionInterface {
  encrypt(data: any, key?: Uint8Array): Promise<EncryptedData>;
  decrypt(encryptedData: EncryptedData, key: Uint8Array): Promise<any>;
  generateKey(): Promise<Uint8Array>;
  generateKeyBase64(): Promise<string>;
  keyFromBase64(base64Key: string): Uint8Array;
  isEncrypted(data: any): data is EncryptedData;
  getPlatformInfo(): PlatformCapabilities;
  test(): Promise<EncryptionTestResult>;
}

// Client Interfaces
export interface AuthClient {
  signUp(credentials: SignUpCredentials): Promise<AuthResponse>;
  signIn(credentials: SignInCredentials): Promise<AuthResponse>;
  signInWithPassword(credentials: SignInCredentials): Promise<AuthResponse>;
  signOut(): Promise<SaintCentralResponse<null>>;
  getSession(): Promise<SaintCentralResponse<AuthSession>>;
  refreshSession(refreshToken?: string): Promise<AuthResponse>;
  resetPassword(email: string): Promise<SaintCentralResponse<null>>;
}

export interface DatabaseClient {
  from<T = any>(table: string): QueryBuilder<T>;
  rpc<T = any>(fn: string, params?: Record<string, any>): Promise<SaintCentralResponse<T>>;
}

export interface SaintCentralClient {
  auth: AuthClient;
  from<T = any>(table: string): QueryBuilder<T>;
  rpc<T = any>(fn: string, params?: Record<string, any>): Promise<SaintCentralResponse<T>>;

  // Utility methods
  getUser(): Promise<AuthUser | null>;
  isAuthenticated(): Promise<boolean>;
  getPlatformInfo(): PlatformInfo;
  healthCheck(): Promise<{
    status: string;
    error?: string;
    platform: PlatformInfo;
    security: {
      encryptionLevel: string;
      strongCryptoRequired: true;
      alwaysEncryptDatabase: true;
    };
  }>;
  onAuthStateChange(
    callback: (event: AuthChangeEvent, session: AuthSession | null) => void,
  ): () => void;
  destroy(): Promise<void>;
}

// Storage Adapters
export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  cleanup(): Promise<void>;
}

// Updated Encryption Adapter (Legacy compatibility)
export interface EncryptionAdapter {
  encrypt(data: any): Promise<EncryptedData>;
  decrypt(encryptedData: EncryptedData): Promise<any>;
  generateKey(): string;
  isEncrypted(data: any): boolean;
  ensureSession(): Promise<void>;
  cleanup(): Promise<void>;
  getEncryptionInfo(): {
    type: string;
    hasSession: boolean;
    sessionExpiry: number | null;
    enabled: boolean;
    supportsEncryption: boolean;
    strongCryptoRequired: true;
    alwaysEncryptDatabase: true;
  };
}

// Factory Function
export interface CreateClientFunction {
  (url: string, config?: SaintCentralConfig): SaintCentralClient;
}

// Error Classes
export declare class SaintCentralError extends Error {
  constructor(message: string, code?: string, details?: any);
  code?: string;
  details?: any;
}

export declare class SaintCentralAuthError extends SaintCentralError {
  constructor(message: string, code?: string, details?: any);
}

export declare class SaintCentralDatabaseError extends SaintCentralError {
  constructor(message: string, code?: string, details?: any);
}

export declare class SaintCentralStorageError extends SaintCentralError {
  constructor(message: string, code?: string, details?: any);
}

export declare class SaintCentralEncryptionError extends SaintCentralError {
  constructor(message: string, code?: string, details?: any);
}

// New Secure Encryption Error Class
export declare class EncryptionError extends Error {
  constructor(message: string, code: string, platform?: string);
  code: string;
  platform?: string;
}

// Secure Encryption Class Declaration
export declare class SecureEncryption implements SecureEncryptionInterface {
  constructor();
  encrypt(data: any, key?: Uint8Array): Promise<EncryptedData>;
  decrypt(encryptedData: EncryptedData, key: Uint8Array): Promise<any>;
  generateKey(): Promise<Uint8Array>;
  generateKeyBase64(): Promise<string>;
  keyFromBase64(base64Key: string): Uint8Array;
  isEncrypted(data: any): data is EncryptedData;
  getPlatformInfo(): PlatformCapabilities;
  test(): Promise<EncryptionTestResult>;
}

// Main exports
export declare const createClient: CreateClientFunction;
export declare const version: string;
export declare const encryption: SecureEncryption;

// Utility Types
export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

// React Native specific (Updated for security)
export interface ReactNativeDependencies {
  asyncStorage: boolean;
  crypto: boolean;
  base64: boolean;
  encryptionLevel: "none" | "strong"; // Removed 'basic'
}

export interface InstallInstructions {
  package: string;
  install: string;
  purpose: string;
  required: boolean;
  note?: string;
}

// Platform Detection Utils
export declare class PlatformDetector {
  constructor();
  getInfo(): PlatformInfo;
  static checkDependencies(): ReactNativeDependencies;
  static getInstallInstructions(): {
    dependencies: ReactNativeDependencies;
    instructions: InstallInstructions[];
    encryptionLevel: string;
  };
}

// Security-focused types
export interface SecurityValidation {
  strongCryptoAvailable: boolean;
  encryptionMethod: string;
  warnings: string[];
  recommendations: InstallInstructions[];
  alwaysEncryptDatabase: true;
}

// Default export
declare const saintCentralSDK: CreateClientFunction;
export default saintCentralSDK;
