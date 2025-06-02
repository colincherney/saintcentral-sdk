#!/usr/bin/env node

/**
 * Saint Central Key Generator
 * Generates secure keys for production deployment
 */

const crypto = require("crypto");

function generateSecureKey(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateJWTSecret(length = 64) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

console.log("🔒 Saint Central - Secure Key Generator");
console.log("=====================================\n");

console.log("📋 Copy these environment variables to your Cloudflare Worker:\n");

console.log("# Required Keys");
console.log(`ENCRYPTION_KEY="${generateSecureKey(32)}"`);
console.log(`JWT_SECRET="${generateJWTSecret(64)}"`);

console.log("\n# Supabase Configuration (replace with your values)");
console.log('SUPABASE_URL="https://your-project.supabase.co"');
console.log('SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"');
console.log('SUPABASE_ANON_KEY="your-anon-key"');

console.log("\n# Database Configuration (replace with your values)");
console.log('DATABASE_URL="postgresql://user:pass@host:port/db"');

console.log("\n# Optional Security Settings");
console.log('RATE_LIMIT_ENABLED="true"');
console.log('MAX_LOGIN_ATTEMPTS="5"');
console.log('LOGIN_LOCKOUT_DURATION="900000"');
console.log('PASSWORD_MIN_LENGTH="12"');

console.log("\n# Optional CORS Settings");
console.log('ALLOWED_ORIGINS="https://yourdomain.com"');

console.log("\n# Optional Monitoring");
console.log('LOG_LEVEL="info"');
console.log('ENABLE_METRICS="true"');

console.log("\n✅ Keys generated successfully!");
console.log("\n⚠️  Security Notes:");
console.log("   • Never commit these keys to version control");
console.log("   • Use different keys for dev/staging/production");
console.log("   • Rotate keys regularly (monthly recommended)");
console.log("   • Store keys securely in environment variables");

console.log("\n📖 For complete setup instructions, see PRODUCTION-SETUP.md");
