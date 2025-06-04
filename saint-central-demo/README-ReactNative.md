# Saint Central SDK - React Native Setup Guide

This guide will help you set up and use the Saint Central SDK in your React Native application.

## Installation

### 1. Install the SDK

```bash
# Copy the SDK file to your project
cp src/sdk.js your-react-native-project/src/
```

### 2. Install Required Dependencies

The SDK works out of the box but for optimal functionality, install these recommended packages:

```bash
# For persistent storage (highly recommended)
npm install @react-native-async-storage/async-storage

# For secure crypto operations (recommended)
npm install expo-crypto
# OR if not using Expo:
npm install react-native-crypto

# For base64 operations (optional - has built-in fallback)
npm install base-64

# For network requests (usually included by default)
# If not available, install:
npm install whatwg-fetch
```

### 3. Platform Setup

#### iOS Setup (if using react-native-crypto)

```bash
cd ios && pod install
```

#### Android Setup

No additional setup required for the recommended packages.

## Basic Usage

### 1. Initialize the Client

```javascript
import {
  createClient,
  createPlatformConfig,
  ReactNativeUtils,
} from "./src/sdk";

// Check what dependencies are available
const deps = ReactNativeUtils.checkDependencies();
console.log("Available dependencies:", deps);

// Get installation instructions for missing packages
const missing = ReactNativeUtils.getInstallInstructions();
if (missing.length > 0) {
  console.log("Consider installing these packages for better functionality:");
  missing.forEach((dep) => {
    console.log(`- ${dep.package}: ${dep.install}`);
    console.log(`  Purpose: ${dep.purpose}`);
  });
}

// Create platform-optimized configuration
const config = createPlatformConfig({
  // Your custom config here
  timeout: 60000, // Longer timeout for mobile networks
});

// Initialize the client
const client = createClient("https://your-api-url.com", config);

// Check platform capabilities
const platformInfo = client.getPlatformInfo();
console.log("Platform info:", platformInfo);
```

### 2. Authentication

```javascript
// Sign up
const signUp = async (email, password) => {
  try {
    const { data, error } = await client.auth.signUp(email, password, {
      // Optional metadata
      deviceType: "mobile",
      platform: "react-native",
    });

    if (error) {
      console.error("Sign up failed:", error);
      return;
    }

    console.log("User signed up:", data);
  } catch (error) {
    console.error("Sign up error:", error);
  }
};

// Sign in
const signIn = async (email, password) => {
  try {
    const { data, error } = await client.auth.signIn(email, password);

    if (error) {
      console.error("Sign in failed:", error);
      return;
    }

    console.log("User signed in:", data);
  } catch (error) {
    console.error("Sign in error:", error);
  }
};

// Check authentication status
const checkAuth = async () => {
  const isAuthenticated = await client.isAuthenticated();
  const user = await client.getUser();

  console.log("Is authenticated:", isAuthenticated);
  console.log("Current user:", user);
};

// Sign out
const signOut = async () => {
  await client.auth.signOut();
  console.log("User signed out");
};
```

### 3. Database Operations

```javascript
// Insert data
const createPost = async (title, content) => {
  try {
    const result = await client.from("posts").insert({
      title,
      content,
      created_at: new Date().toISOString(),
    });

    console.log("Post created:", result);
  } catch (error) {
    console.error("Failed to create post:", error);
  }
};

// Query data
const getPosts = async () => {
  try {
    const posts = await client
      .from("posts")
      .select("*")
      .order("created_at", "desc")
      .limit(10);

    console.log("Posts:", posts);
    return posts;
  } catch (error) {
    console.error("Failed to get posts:", error);
    return [];
  }
};

// Update data
const updatePost = async (id, updates) => {
  try {
    const result = await client.from("posts").update(updates).eq("id", id);

    console.log("Post updated:", result);
  } catch (error) {
    console.error("Failed to update post:", error);
  }
};

// Delete data
const deletePost = async (id) => {
  try {
    await client.from("posts").delete().eq("id", id);

    console.log("Post deleted");
  } catch (error) {
    console.error("Failed to delete post:", error);
  }
};
```

## React Native Component Example

```javascript
import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Alert,
  StyleSheet,
} from "react-native";
import { createClient, createPlatformConfig } from "./src/sdk";

const client = createClient("https://your-api-url.com", createPlatformConfig());

export default function AuthScreen() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const authenticated = await client.isAuthenticated();
      const currentUser = await client.getUser();

      setIsAuthenticated(authenticated);
      setUser(currentUser);
    } catch (error) {
      console.error("Auth check failed:", error);
    }
  };

  const handleSignIn = async () => {
    try {
      const { data, error } = await client.auth.signIn(email, password);

      if (error) {
        Alert.alert("Sign In Failed", error);
        return;
      }

      Alert.alert("Success", "Signed in successfully!");
      await checkAuthStatus();
    } catch (error) {
      Alert.alert("Error", error.message);
    }
  };

  const handleSignUp = async () => {
    try {
      const { data, error } = await client.auth.signUp(email, password);

      if (error) {
        Alert.alert("Sign Up Failed", error);
        return;
      }

      Alert.alert("Success", "Account created successfully!");
      await checkAuthStatus();
    } catch (error) {
      Alert.alert("Error", error.message);
    }
  };

  const handleSignOut = async () => {
    try {
      await client.auth.signOut();
      Alert.alert("Success", "Signed out successfully!");
      await checkAuthStatus();
    } catch (error) {
      Alert.alert("Error", error.message);
    }
  };

  if (isAuthenticated) {
    return (
      <View style={styles.container}>
        <Text style={styles.title}>Welcome!</Text>
        <Text style={styles.subtitle}>Email: {user?.email}</Text>

        <TouchableOpacity style={styles.button} onPress={handleSignOut}>
          <Text style={styles.buttonText}>Sign Out</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Saint Central Auth</Text>

      <TextInput
        style={styles.input}
        placeholder="Email"
        value={email}
        onChangeText={setEmail}
        keyboardType="email-address"
        autoCapitalize="none"
      />

      <TextInput
        style={styles.input}
        placeholder="Password"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
      />

      <TouchableOpacity style={styles.button} onPress={handleSignIn}>
        <Text style={styles.buttonText}>Sign In</Text>
      </TouchableOpacity>

      <TouchableOpacity
        style={[styles.button, styles.secondaryButton]}
        onPress={handleSignUp}
      >
        <Text style={styles.buttonText}>Sign Up</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: "center",
    padding: 20,
    backgroundColor: "#f5f5f5",
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    textAlign: "center",
    marginBottom: 10,
  },
  subtitle: {
    fontSize: 16,
    textAlign: "center",
    marginBottom: 30,
    color: "#666",
  },
  input: {
    backgroundColor: "white",
    padding: 15,
    borderRadius: 8,
    marginBottom: 15,
    borderWidth: 1,
    borderColor: "#ddd",
  },
  button: {
    backgroundColor: "#007AFF",
    padding: 15,
    borderRadius: 8,
    marginBottom: 10,
  },
  secondaryButton: {
    backgroundColor: "#34C759",
  },
  buttonText: {
    color: "white",
    textAlign: "center",
    fontWeight: "bold",
    fontSize: 16,
  },
});
```

## Error Handling

The SDK includes built-in error handling, but you can also use the error-wrapped version:

```javascript
import { createClientWithErrorHandling } from "./src/sdk";

const client = createClientWithErrorHandling("https://your-api-url.com");

// All methods will return { data, error } format
const { data, error } = await client.auth.signIn(email, password);
if (error) {
  console.error("Sign in failed:", error);
} else {
  console.log("Sign in successful:", data);
}
```

## Platform-Specific Considerations

### Storage

- **With AsyncStorage**: Persistent auth tokens across app restarts
- **Without AsyncStorage**: Auth tokens stored in memory (lost on app restart)

### Encryption

- **With crypto packages**: Secure encryption for auth operations
- **Without crypto packages**: Falls back to unencrypted mode (still secure over HTTPS)

### Network

- React Native has longer default timeouts due to mobile network conditions
- The SDK automatically adjusts timeouts and retry logic for mobile

## Troubleshooting

### Common Issues

1. **"localStorage is not defined"**

   - This is normal in React Native. The SDK automatically uses AsyncStorage or memory storage.

2. **"crypto.subtle is not available"**

   - Install `expo-crypto` or `react-native-crypto` for encryption support.
   - The SDK will work without encryption but with reduced security.

3. **"AbortSignal.timeout is not a function"**

   - This is handled automatically by the SDK's timeout implementation.

4. **Network requests failing**
   - Check your API URL is correct and accessible
   - Ensure your React Native app has network permissions
   - Try increasing the timeout in your config

### Debug Mode

Enable debug logging to troubleshoot issues:

```javascript
const client = createClient("https://your-api-url.com", {
  debug: true,
  timeout: 60000,
});

// Check platform capabilities
console.log("Platform info:", client.getPlatformInfo());
```

## Best Practices

1. **Always handle errors gracefully**
2. **Use AsyncStorage for production apps**
3. **Install crypto packages for better security**
4. **Set appropriate timeouts for your network conditions**
5. **Check authentication status on app startup**
6. **Use the error-wrapped client for simpler error handling**

## Support

If you encounter issues specific to React Native, please check:

1. Your React Native version compatibility
2. Required dependencies are properly installed
3. Platform-specific setup is complete
4. Network permissions are configured

For more help, refer to the main SDK documentation or create an issue in the repository.
