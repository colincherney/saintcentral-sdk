import { createClient } from "./sdk.js";

// Create the client with security features enabled
const client = createClient(
  "https://saint-central-api.colinmcherney.workers.dev",
  {
    security: {
      encryption: true,
      rateLimit: true,
      jwtHardening: true,
      ddosProtection: true,
      headerSecurity: true,
    },
  }
);

// Display initial status
document.getElementById("result").textContent =
  "Saint Central SDK initialized with encryption.";

// Set up login button
document.getElementById("login-btn").addEventListener("click", async () => {
  try {
    document.getElementById("result").textContent = "Logging in...";

    // Use signInWithPassword method with Supabase v2 compatibility
    const { data, error } = await client.auth.signInWithPassword({
      email: "test2@gmail.com",
      password: "123456",
      gotrue_meta_security: {}, // Required for Supabase v2 compatibility
    });

    // Display the result
    if (error) {
      document.getElementById("result").textContent = `Login failed: ${
        error.message || "Unknown error"
      }`;
    } else if (data) {
      document.getElementById(
        "result"
      ).textContent = `Login successful! User: ${
        data.user?.email || "Unknown"
      }`;
    } else {
      document.getElementById("result").textContent =
        "Login completed with no data returned.";
    }

    // Log full result for debugging
    console.log("Login result:", { data, error });
  } catch (e) {
    document.getElementById("result").textContent = `Error: ${e.message}`;
    console.error("Login error:", e);
  }
});
