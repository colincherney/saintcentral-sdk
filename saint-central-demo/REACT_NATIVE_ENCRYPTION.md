# React Native Encryption Guide

The Saint Central SDK now provides **full encryption support for React Native** with automatic fallbacks to ensure your authentication operations are always secure.

## 🔐 Encryption Levels

### Strong Encryption (Recommended)

Install one of these packages for the best security:

```bash
# Option 1: Expo Crypto (recommended for Expo projects)
npm install expo-crypto

# Option 2: React Native Crypto (for bare React Native)
npm install react-native-crypto
```

### Basic Encryption (Automatic Fallback)

If no crypto libraries are available, the SDK automatically uses enhanced XOR encryption with:

- Multiple encryption rounds
- Salt generation
- Key stretching
- Better than no encryption at all

## 📦 Required Dependencies

```bash
# Required for persistent auth storage
npm install @react-native-async-storage/async-storage

# Optional but recommended for better performance
npm install base-64
```

## 🚀 Quick Setup

```javascript
import { createClient, ReactNativeUtils } from "./src/sdk.js";

// Check your encryption setup
const setupStatus = await ReactNativeUtils.verifySetup();
console.log("Encryption ready:", setupStatus.ready);

// Create client - encryption is automatically enabled
const client = createClient("https://your-api.com");

// All auth operations are automatically encrypted
const { data, error } = await client.auth.signUp(
  "user@example.com",
  "password123"
);
```

## 🔍 Verify Your Setup

```javascript
import { ReactNativeUtils } from "./src/sdk.js";

// Check what's available
const deps = ReactNativeUtils.checkDependencies();
console.log("Encryption level:", deps.encryptionLevel);

// Get detailed setup info
const instructions = ReactNativeUtils.getInstallInstructions();
console.log(instructions.summary);

// Run full verification (logs to console)
await ReactNativeUtils.verifySetup();
```

## 🛡️ Security Features

### Automatic Encryption

- **All authentication operations** (signUp, signIn, resetPassword) are automatically encrypted
- **Session management** uses encrypted storage
- **Graceful degradation** ensures functionality even without crypto libraries

### Platform Detection

- Automatically detects React Native environment
- Uses platform-appropriate encryption methods
- Falls back gracefully when libraries are unavailable

### Multiple Encryption Methods

1. **AES-256-CBC** (with react-native-crypto)
2. **SHA-256 + XOR** (with expo-crypto)
3. **Enhanced XOR** (fallback, always available)

## 📱 Platform Information

```javascript
const client = createClient("https://your-api.com");
const info = client.getPlatformInfo();

console.log("Platform:", info.isReactNative ? "React Native" : "Other");
console.log("Encryption available:", info.authEncryptionEnabled);
console.log("Encryption method:", info.encryption.method);
console.log("Encryption level:", info.encryption.level);
```

## 🔧 Troubleshooting

### "Session required for auth operations"

This means the SDK couldn't establish a secure session with the server. Check:

- Network connectivity
- Server endpoint is correct
- Server supports the `/auth/key-exchange` endpoint

### Low encryption level

If you're getting 'basic' encryption level:

```bash
# Install a crypto library for stronger encryption
npm install expo-crypto
# or
npm install react-native-crypto
```

### AsyncStorage warnings

```bash
# Install AsyncStorage for persistent auth storage
npm install @react-native-async-storage/async-storage
```

## 🎯 Best Practices

1. **Install crypto dependencies** for production apps
2. **Test encryption setup** during development
3. **Handle auth errors gracefully** in your UI
4. **Use HTTPS endpoints** for additional transport security

## 📊 Example Output

```
🔐 Saint Central React Native Encryption Status:
📊 Encryption Level: strong
✅ AsyncStorage: Available
🔒 Crypto: Available
📝 Base64: Native

Encryption level: strong. Your setup provides strong encryption for auth operations.

💡 Recommended for Better Security:
   expo-crypto (recommended): npm install expo-crypto
      Provides SHA-256 hashing and secure random generation
```

## 🔄 Migration from Previous Versions

If you were using an older version where React Native encryption was disabled:

1. **No code changes needed** - encryption is now automatic
2. **Install crypto dependencies** for better security
3. **Run verification** to check your setup
4. **Update your error handling** if needed

The SDK maintains backward compatibility while adding encryption support.
