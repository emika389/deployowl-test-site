export default {
  async fetch(request, env) {
    // 1. Invoke Owl Guard security
    try {
      if (env.OWL_GUARD) {
        const decision = await env.OWL_GUARD.decision(request);
        if (decision.blocked) {
          if (decision.reason === "challenge") {
            return new Response(decision.html, {
              status: 200,
              headers: { "Content-Type": "text/html; charset=utf-8" }
            });
          }
          return new Response(JSON.stringify({ error: "Access Denied by OwlGuard Edge Firewall WAF", reason: decision.reason }), {
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }
      }
    } catch (guardErr) {
      console.error("OwlGuard WAF bypassed/failed:", guardErr);
    }

    const url = new URL(request.url);
    const action = url.searchParams.get("action");

    // Enable CORS for easy client testing
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Default route
    if (!action) {
      return new Response(JSON.stringify({
        status: "online",
        message: "Welcome to DeployOwl Test Site API gateway protected by OwlGuard.",
        features: ["nosql", "storage", "guard"],
        timestamp: new Date().toISOString()
      }), { headers: corsHeaders });
    }

    try {
      const db = env.OWL_NOSQL;

      if (action === "signup") {
        if (request.method !== "POST") {
          return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: corsHeaders });
        }
        const { email, password } = await request.json();
        if (!email || !password) {
          return new Response(JSON.stringify({ error: "Missing email or password" }), { status: 400, headers: corsHeaders });
        }

        // Sanitize email key for OwlNoSQL
        const cleanId = email.replace(/[^a-zA-Z0-9_\-]/g, "_");

        // Check if user exists
        const existing = await db.collection("users").find(cleanId);
        if (existing) {
          return new Response(JSON.stringify({ error: "User already exists" }), { status: 409, headers: corsHeaders });
        }

        // Insert
        await db.collection("users").insert(cleanId, { email, password, registeredAt: new Date().toISOString() });
        return new Response(JSON.stringify({ success: true, message: "User registered successfully" }), { headers: corsHeaders });
      }

      if (action === "login") {
        if (request.method !== "POST") {
          return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: corsHeaders });
        }
        const { email, password } = await request.json();
        if (!email || !password) {
          return new Response(JSON.stringify({ error: "Missing email or password" }), { status: 400, headers: corsHeaders });
        }

        const cleanId = email.replace(/[^a-zA-Z0-9_\-]/g, "_");
        const user = await db.collection("users").find(cleanId);
        if (!user || user.password !== password) {
          return new Response(JSON.stringify({ error: "Invalid email or password" }), { status: 401, headers: corsHeaders });
        }

        return new Response(JSON.stringify({ success: true, message: "Login successful", user: { email: user.email } }), { headers: corsHeaders });
      }

      if (action === "upload") {
        if (request.method !== "POST") {
          return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405, headers: corsHeaders });
        }

        const formData = await request.formData();
        const file = formData.get("file");
        if (!file) {
          return new Response(JSON.stringify({ error: "No file uploaded" }), { status: 400, headers: corsHeaders });
        }

        const arrayBuffer = await file.arrayBuffer();
        const originalName = file.name || "upload.png";
        const cleanName = originalName.replace(/[^a-zA-Z0-9._\-]/g, "_");
        const uniqueName = `${Date.now()}-${cleanName}`;
        const contentType = file.type || "application/octet-stream";

        const uploadResult = await env.OWL_STORAGE.put(uniqueName, arrayBuffer, { contentType });
        
        const origin = url.origin;
        const publicUrl = `${origin}/_cdn/storage/${uniqueName}`;

        return new Response(JSON.stringify({
          success: true,
          fileName: uniqueName,
          url: publicUrl,
          rawResult: uploadResult
        }), { headers: corsHeaders });
      }

      return new Response(JSON.stringify({ error: "Invalid action" }), { status: 400, headers: corsHeaders });

    } catch (err) {
      return new Response(JSON.stringify({ error: "Internal Error", details: err.message }), { status: 500, headers: corsHeaders });
    }
  }
};
