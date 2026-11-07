
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";

const ROOT = __dirname;
const DB_FILE = path.join(ROOT, "slxm-database.json");

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";

const MODELS = {
  chat: "openai/gpt-oss-120b",
  lite: "openai/gpt-oss-20b",
  reason: "openai/gpt-oss-120b",
  vision: "meta-llama/llama-4-scout-17b-16e-instruct"
};

// DATABASE

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return { users: [], sessions: {} };
  }
}

let db = loadDB();

function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// RESPONSE

function send(res, status, data, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  });

  res.end(JSON.stringify(data));
}

// READ REQUEST BODY

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

// USER AUTHENTICATION

function getUser(req) {
  const token = getCookies(req).slxm_session;

  if (!token) return null;

  const tokenHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  const session = db.sessions[tokenHash];

  if (!session || session.expires < Date.now()) {
    delete db.sessions[tokenHash];
    saveDB();
    return null;
  }

  return db.users.find(user => user.id === session.userId) || null;
}

function makeSession(user, res) {
  const token = crypto.randomBytes(32).toString("hex");

  const tokenHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  db.sessions[tokenHash] = {
    userId: user.id,
    expires: Date.now() + 30 * 24 * 60 * 60 * 1000
  };

  saveDB();

  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";

  res.setHeader(
    "Set-Cookie",
    `slxm_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${secure}`
  );
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
  const result = await hashPassword(password, user.salt);

  const a = Buffer.from(result.hash, "hex");
  const b = Buffer.from(user.passwordHash, "hex");

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

// GROQ MESSAGE CONVERSION

function makeGroqMessages(messages, mode) {
  const systemPrompt =
    "You are SLXM AI, an assistant created by Saa​​im Saroar. " +
    "Your name is SLXM AI. " +
    "Never claim to be Llama, Ollama, Groq or another AI model. " +
    "Be helpful, friendly, clear, accurate and natural.";

  const converted = messages.slice(-30).map(m => {
    const role = m.role === "assistant" ? "assistant" : "user";

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

      if (db.users.some(u => u.email === email)) {
        return send(res, 409, {
          error: "An account with that email already exists. Try logging in."
        });
      }

      const credentials = await hashPassword(password);

      const user = {
        id: crypto.randomUUID(),
        username,
        email,
        salt: credentials.salt,
        passwordHash: credentials.hash,
        chats: []
      };

      db.users.push(user);

      makeSession(user, res);
      saveDB();

      return send(res, 201, {
        user: publicUser(user)
      });
    }

    // LOG IN

    if (req.method === "POST" && pathname === "/api/login") {
      const body = await readBody(req);

      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const user = db.users.find(u => u.email === email);

      if (!user || !(await checkPassword(password, user))) {
        return send(res, 401, {
          error: "Email or password is incorrect."
        });
      }

      makeSession(user, res);

      return send(res, 200, {
        user: publicUser(user)
      });
    }

    // LOG OUT

    if (req.method === "POST" && pathname === "/api/logout") {
      const token = getCookies(req).slxm_session;

      if (token) {
        const tokenHash = crypto
          .createHash("sha256")
          .update(token)
          .digest("hex");

        delete db.sessions[tokenHash];
        saveDB();
      }

      return send(res, 200, { ok: true }, {
        "Set-Cookie":
          "slxm_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
      });
    }

    // CURRENT USER

    if (req.method === "GET" && pathname === "/api/me") {
      const user = getUser(req);

      return send(res, 200, {
        user: user ? publicUser(user) : null
      });
    }

    // GET SAVED CHATS

    if (req.method === "GET" && pathname === "/api/chats") {
      const user = getUser(req);

      if (!user) {
        return send(res, 401, {
          error: "Please log in first."
        });
      }

      return send(res, 200, {
        chats: user.chats || []
      });
    }

    // SAVE CHATS

    if (req.method === "PUT" && pathname === "/api/chats") {
      const user = getUser(req);

      if (!user) {
        return send(res, 401, {
          error: "Please log in first."
        });
      }

      const body = await readBody(req);

      user.chats = Array.isArray(body.chats)
        ? body.chats.slice(0, 100)
        : [];

      saveDB();

      return send(res, 200, { ok: true });
    }

    // SLXM AI CHAT - GROQ

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
          error: "Groq API key is missing. Set GROQ_API_KEY and restart SLXM."
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

        const message =
          result.error?.message ||
          result.error ||
          "Groq could not answer.";

        return send(res, 502, {
          error: String(message)
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
      error: error.message || "Server error."
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
  const url = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  const pathname = decodeURIComponent(url.pathname);

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
  console.log(" SLXM AI is running!");
  console.log(` http://localhost:${PORT}`);
  console.log(` AI provider: Groq`);
  console.log(` Main model: ${MODELS.chat}`);
  console.log("--------------------------------------");
});
