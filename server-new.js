
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const ROOT = __dirname;

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";

const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SUPABASE_KEY = process.env.SUPABASE_SECRET_KEY || "";

const MODELS = {
  chat: "openai/gpt-oss-120b",
  lite: "openai/gpt-oss-20b",
  reason: "openai/gpt-oss-120b",
  vision: "meta-llama/llama-4-scout-17b-16e-instruct"
};

// SUPABASE CONNECTION

async function supabase(table, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error("Supabase environment variables are missing.");
  }

  const response = await fetch(
    `${SUPABASE_URL}/rest/v1/${table}`,
    {
      ...options,
      headers: {
        "apikey": SUPABASE_KEY,
        "Content-Type": "application/json",
        ...options.headers
      }
    }
  );

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    console.error("Supabase error:", data);

    throw new Error(
      data?.message ||
      data?.hint ||
      "Supabase database request failed."
    );
  }

  return data;
}

// RESPONSE

function send(res, status, data, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  });

  res.end(JSON.stringify(data));
}

// REQUEST BODY

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (body.length > 12 * 1024 * 1024) {
        reject(new Error("Request too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

// COOKIES

function getCookies(req) {
  const result = {};

  (req.headers.cookie || "").split(";").forEach(part => {
    const i = part.indexOf("=");

    if (i > -1) {
      result[part.slice(0, i).trim()] =
        decodeURIComponent(part.slice(i + 1).trim());
    }
  });

  return result;
}

function makeCookie(token) {
  const secure =
    process.env.NODE_ENV === "production" ? "; Secure" : "";

  return `slxm_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secure}`;
}

function clearCookie() {
  const secure =
    process.env.NODE_ENV === "production" ? "; Secure" : "";

  return `slxm_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`;
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

// PASSWORDS

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString("hex")
) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) return reject(err);

      resolve({
        salt,
        hash: key.toString("hex")
      });
    });
  });
}

async function checkPassword(password, user) {
  const result = await hashPassword(
    password,
    user.password_salt
  );

  const a = Buffer.from(result.hash, "hex");
  const b = Buffer.from(user.password_hash, "hex");

  return a.length === b.length &&
    crypto.timingSafeEqual(a, b);
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email
  };
}

// LOGIN SESSIONS

async function makeSession(user, res) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);

  const expiresAt = new Date(
    Date.now() + 30 * 24 * 60 * 60 * 1000
  ).toISOString();

  await supabase("slxm_sessions", {
    method: "POST",
    headers: {
      "Prefer": "return=minimal"
    },
    body: JSON.stringify({
      token_hash: tokenHash,
      user_id: user.id,
      expires_at: expiresAt
    })
  });

  res.setHeader("Set-Cookie", makeCookie(token));
}

async function getUser(req) {
  const token = getCookies(req).slxm_session;

  if (!token) return null;

  const tokenHash = hashToken(token);

  const sessions = await supabase(
    `slxm_sessions?select=user_id,expires_at&token_hash=eq.${encodeURIComponent(tokenHash)}&limit=1`
  );

  const session = sessions?.[0];

  if (!session) return null;

  if (new Date(session.expires_at).getTime() < Date.now()) {
    await supabase(
      `slxm_sessions?token_hash=eq.${encodeURIComponent(tokenHash)}`,
      { method: "DELETE" }
    );

    return null;
  }

  const users = await supabase(
    `slxm_users?select=id,username,email&id=eq.${encodeURIComponent(session.user_id)}&limit=1`
  );

  return users?.[0] || null;
}

// GROQ MESSAGES

function makeGroqMessages(messages, mode) {
  const systemPrompt =
    "You are SLXM AI, an assistant created by Saaim Saroar. " +
    "Your name is SLXM AI. " +
    "Never claim to be Llama, Ollama, Groq or another AI model. " +
    "Be helpful, friendly, clear, accurate and natural.";

  const converted = messages.slice(-30).map(m => {
    const role =
      m.role === "assistant" ? "assistant" : "user";

    const content = String(m.content || "");

    if (m.image && role === "user") {
      return {
        role,
        content: [
          {
            type: "text",
            text: content || "Please describe this image."
          },
          {
            type: "image_url",
            image_url: {
              url: String(m.image)
            }
          }
        ]
      };
    }

    return {
      role,
      content
    };
  });

  let finalSystemPrompt = systemPrompt;

  if (mode === "reason") {
    finalSystemPrompt +=
      " Think carefully before answering. " +
      "Give clear, well-structured answers. " +
      "Do not reveal private chain-of-thought.";
  }

  converted.unshift({
    role: "system",
    content: finalSystemPrompt
  });

  return converted;
}
// SLXM VIDS - MAGIC HOUR VIDEO ENGINE

const MAGIC_HOUR_URL = "https://api.magichour.ai";

const videoRequestTimes = new Map();

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function canGenerateVideo(req) {
  const ip = req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;

  const recent = (videoRequestTimes.get(ip) || [])
    .filter(time => now - time < oneHour);

  if (recent.length >= 2) {
    videoRequestTimes.set(ip, recent);
    return false;
  }

  recent.push(now);
  videoRequestTimes.set(ip, recent);
  return true;
}

async function magicHourRequest(endpoint, options = {}) {
  const apiKey = process.env.MAGIC_HOUR_API_KEY;

  const response = await fetch(
    `${MAGIC_HOUR_URL}${endpoint}`,
    {
      ...options,
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
        ...options.headers
      }
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(
      data.message ||
      data.error?.message ||
      "Magic Hour video request failed."
    );

    error.status = response.status;
    error.code = data.code;

    throw error;
  }

  return data;
}

async function createSLXMVideo(body) {
  const duration = [5, 10, 15].includes(Number(body.duration))
    ? Number(body.duration)
    : 5;

  const aspectRatio = ["16:9", "9:16", "1:1"].includes(body.aspectRatio)
    ? body.aspectRatio
    : "16:9";

  // Use the free-tier LTX model at 480p.
  const created = await magicHourRequest("/v1/text-to-video", {
    method: "POST",
    body: JSON.stringify({
      end_seconds: duration,
      aspect_ratio: aspectRatio,
      model: "ltx-2.5",
      resolution: "480p",
      audio: true,
      name: "SLXM VIDS - VERSION X",
      style: {
        prompt: String(body.prompt).trim()
      }
    })
  });

  if (!created.id) {
    throw new Error("Magic Hour did not return a video project ID.");
  }

  console.log(
    "SLXM VIDS project created:",
    created.id,
    "| Estimated credits:",
    created.credits_charged
  );

  // Check the project until the video is ready.
  // Maximum wait: approximately five minutes.
  for (let attempt = 0; attempt < 60; attempt++) {
    await wait(5000);

    const project = await magicHourRequest(
      `/v1/video-projects/${encodeURIComponent(created.id)}`
    );

    if (project.status === "complete") {
      const videoUrl = project.downloads?.[0]?.url;

      if (!videoUrl) {
        throw new Error(
          "The video finished, but Magic Hour did not return a download URL."
        );
      }

      return {
        videoUrl,
        projectId: created.id,
        creditsCharged: project.credits_charged
      };
    }

    if (
      project.status === "error" ||
      project.status === "canceled"
    ) {
      throw new Error(
        project.error?.message ||
        `Video generation ended with status: ${project.status}`
      );
    }

    console.log(
      `SLXM VIDS: ${project.status || "processing"} (${attempt + 1}/60)`
    );
  }

  const timeoutError = new Error(
    "Your video is still processing. Please try checking again later."
  );

  timeoutError.projectId = created.id;

  throw timeoutError;
}
// API ROUTES

async function api(req, res, pathname) {
  try {

    // SIGN UP

    if (req.method === "POST" && pathname === "/api/signup") {
      const body = await readBody(req);

      const username = String(body.username || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (username.length < 2 || username.length > 30) {
        return send(res, 400, {
          error: "Username must be 2–30 characters."
        });
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return send(res, 400, {
          error: "Please enter a valid email address."
        });
      }

      if (password.length < 8 || password.length > 128) {
        return send(res, 400, {
          error: "Password must be at least 8 characters."
        });
      }

      const existing = await supabase(
        `slxm_users?select=id&email=eq.${encodeURIComponent(email)}&limit=1`
      );

      if (existing?.length) {
        return send(res, 409, {
          error: "An account with that email already exists. Try logging in."
        });
      }

      const credentials = await hashPassword(password);

      const created = await supabase("slxm_users", {
        method: "POST",
        headers: {
          "Prefer": "return=representation"
        },
        body: JSON.stringify({
          username,
          email,
          password_hash: credentials.hash,
          password_salt: credentials.salt
        })
      });

      const user = created?.[0];

      if (!user) {
        throw new Error("Could not create your account.");
      }

      await makeSession(user, res);

      return send(res, 201, {
        user: publicUser(user)
      });
    }

    // LOG IN

    if (req.method === "POST" && pathname === "/api/login") {
      const body = await readBody(req);

      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const users = await supabase(
        `slxm_users?select=id,username,email,password_hash,password_salt&email=eq.${encodeURIComponent(email)}&limit=1`
      );

      const user = users?.[0];

      if (
        !user ||
        !user.password_salt ||
        !(await checkPassword(password, user))
      ) {
        return send(res, 401, {
          error: "Email or password is incorrect."
        });
      }

      await makeSession(user, res);

      return send(res, 200, {
        user: publicUser(user)
      });
    }

    // LOG OUT

    if (req.method === "POST" && pathname === "/api/logout") {
      const token = getCookies(req).slxm_session;

      if (token) {
        await supabase(
          `slxm_sessions?token_hash=eq.${encodeURIComponent(hashToken(token))}`,
          { method: "DELETE" }
        );
      }

      return send(res, 200, { ok: true }, {
        "Set-Cookie": clearCookie()
      });
    }

    // CURRENT USER

    if (req.method === "GET" && pathname === "/api/me") {
      const user = await getUser(req);

      return send(res, 200, {
        user: user ? publicUser(user) : null
      });
    }

    // GET SAVED CHATS

    if (req.method === "GET" && pathname === "/api/chats") {
      const user = await getUser(req);

      if (!user) {
        return send(res, 401, {
          error: "Please log in first."
        });
      }

      const rows = await supabase(
        `slxm_chats?select=chats&user_id=eq.${encodeURIComponent(user.id)}&limit=1`
      );

      return send(res, 200, {
        chats: rows?.[0]?.chats || []
      });
    }

    // SAVE CHATS

    if (req.method === "PUT" && pathname === "/api/chats") {
      const user = await getUser(req);

      if (!user) {
        return send(res, 401, {
          error: "Please log in first."
        });
      }

      const body = await readBody(req);

      const chats = Array.isArray(body.chats)
        ? body.chats.slice(0, 100)
        : [];

      await supabase("slxm_chats?on_conflict=user_id", {
        method: "POST",
        headers: {
          "Prefer": "resolution=merge-duplicates,return=minimal"
        },
        body: JSON.stringify({
          user_id: user.id,
          chats,
          updated_at: new Date().toISOString()
        })
      });

      return send(res, 200, { ok: true });
    }
// SLXM VIDS - GENERATE VIDEO

if (
  req.method === "POST" &&
  pathname === "/api/video/generate"
) {
  if (!process.env.MAGIC_HOUR_API_KEY) {
    return send(res, 503, {
      error: "Magic Hour API key is missing. Add MAGIC_HOUR_API_KEY to your server environment."
    });
  }

  if (!canGenerateVideo(req)) {
    return send(res, 429, {
      error: "Video limit reached. Please try again in an hour."
    });
  }

  const body = await readBody(req);

  const prompt = String(body.prompt || "").trim();

  if (!prompt) {
    return send(res, 400, {
      error: "Please describe the video you want to create."
    });
  }

  if (prompt.length > 1500) {
    return send(res, 400, {
      error: "Your video description must be 1500 characters or fewer."
    });
  }

  if (body.mode === "image-to-video") {
    return send(res, 501, {
      error: "Image-to-video is not connected yet. Text-to-video is ready for integration."
    });
  }

  try {
    const result = await createSLXMVideo({
      prompt,
      duration: body.duration,
      aspectRatio: body.aspectRatio
    });

    return send(res, 200, {
      videoUrl: result.videoUrl,
      projectId: result.projectId,
      creditsCharged: result.creditsCharged
    });

  } catch (error) {
    console.error("SLXM VIDS error:", error);

    if (error.projectId) {
      return send(res, 504, {
        error: error.message,
        projectId: error.projectId
      });
    }

    return send(
      res,
      error.status === 402 ? 402 :
      error.status === 401 ? 502 :
      502,
      {
        error: error.message
      }
    );
  }
}
    // SLXM AI CHAT

    if (req.method === "POST" && pathname === "/api/chat") {
      const body = await readBody(req);

      const messages = Array.isArray(body.messages)
        ? body.messages
        : [];

      const mode = String(body.mode || "chat").toLowerCase();

      if (!messages.length) {
        return send(res, 400, {
          error: "Write a message first."
        });
      }

      const apiKey = process.env.GROQ_API_KEY;

      if (!apiKey) {
        return send(res, 503, {
          error: "Groq API key is missing."
        });
      }

      const model = MODELS[mode] || MODELS.chat;

      if (
        mode === "vision" &&
        !messages.some(m => m.image)
      ) {
        return send(res, 400, {
          error: "Attach an image to use Vision mode."
        });
      }

      let response;

      try {
        response = await fetch(GROQ_URL, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            model,
            messages: makeGroqMessages(messages, mode),
            stream: false,
            max_completion_tokens:
              mode === "reason" ? 1800 : 1200
          })
        });
      } catch (error) {
        console.error("Groq connection error:", error);

        return send(res, 503, {
          error: "SLXM could not connect to Groq. Check your internet connection."
        });
      }

      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        console.error("Groq API error:", result);

        return send(res, 502, {
          error: String(
            result.error?.message ||
            result.error ||
            "Groq could not answer."
          )
        });
      }

      const reply = result.choices?.[0]?.message?.content;

      return send(res, 200, {
        reply:
          typeof reply === "string" && reply.trim()
            ? reply
            : "I couldn't generate a reply."
      });
    }

    return send(res, 404, {
      error: "API route not found."
    });

  } catch (error) {
    console.error("API error:", error);

    return send(res, 500, {
      error: "Server error. Check the CMD logs."
    });
  }
}

// WEBSITE FILES

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

// SERVER

const server = http.createServer(async (req, res) => {
  let url;

  try {
    url = new URL(
      req.url,
      `http://${req.headers.host || "localhost"}`
    );
  } catch {
    res.writeHead(400);
    return res.end("Bad request");
  }

  let pathname;

  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    res.writeHead(400);
    return res.end("Bad request");
  }

  if (pathname.startsWith("/api/")) {
    return api(req, res, pathname);
  }

  const requested =
    pathname === "/" ? "index.html" : pathname.slice(1);

  const filePath = path.resolve(ROOT, requested);

  if (
    !filePath.startsWith(ROOT + path.sep) &&
    filePath !== path.join(ROOT, "index.html")
  ) {
    res.writeHead(403);
    return res.end("Forbidden");
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, {
        "Content-Type": "text/plain; charset=utf-8"
      });

      return res.end("File not found");
    }

    res.writeHead(200, {
      "Content-Type":
        mimeTypes[path.extname(filePath).toLowerCase()] ||
        "application/octet-stream"
    });

    res.end(data);
  });
});

// START SLXM

server.listen(PORT, HOST, () => {
  console.log("--------------------------------------");
  console.log(" SLXM AI server is running!");
  console.log(` Port: ${PORT}`);
  console.log(" AI provider: Groq");
  console.log(` Main model: ${MODELS.chat}`);
  console.log(
    ` Supabase: ${SUPABASE_URL && SUPABASE_KEY ? "Configured" : "NOT CONFIGURED"}`
  );
  console.log("--------------------------------------");
});
