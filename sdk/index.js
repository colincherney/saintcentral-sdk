/**
 * Saint Central SDK - Secure Entry Point
 * @version 3.0.0
 */

export { createClient, SaintCentralClient } from "./client.js";
export { AuthClient } from "./auth.js";
export { DatabaseClient, QueryBuilder } from "./database.js";
export { EncryptionManager } from "./encryption.js";
export { StorageAdapter, RequestManager, PlatformDetector } from "./infrastructure.js";

// Error classes
export {
  SaintCentralError,
  SaintCentralAuthError,
  SaintCentralDatabaseError,
  SaintCentralStorageError,
  SaintCentralEncryptionError,
} from "./client.js";

export const version = "3.0.0";
export { createClient as default } from "./client.js";
