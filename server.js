// ===================================
// MMKK AI - Complete Server
// ===================================

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { pool, initDatabase } = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;
const KIRA_BASE = "https://kiraai.vn/api/v1";
const API_KEY = process.env.KIRA_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

app.disable("x-powered-by");

app.use(express.json({
  limit: "12mb"
}));

app.use(cookieParser());

app.use(express.static(
  path.join(__dirname, "public")
));

// ===================================
// Helpers
// ===================================

function validateUsername(username) {
  return (
    typeof username === "string" &&
    /^[a-zA-Z0-9_]{3,30}$/.test(username)
  );
}

function validatePassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128
  );
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function setLoginCookie(res, user) {
  const token = createToken(user);

  res.cookie("mmkk_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}

function auth(req, res, next) {
  try {
    const token = req.cookies.mmkk_session;

    if (!token) {
      return res.status(401).json({
        error: "ابتدا وارد حساب شوید."
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;
    next();

  } catch {
    res.status(401).json({
      error: "نشست شما منقضی شده است."
    });
  }
}

function validatePrompt(prompt) {
  return (
    typeof prompt === "string" &&
    prompt.trim().length > 0 &&
    prompt.length <= 4000
  );
}

function validateReferences(references) {
  if (references === undefined) return true;

  if (!Array.isArray(references) ||
      references.length > 2) {
    return false;
  }

  return references.every(ref =>
    ref &&
    ["image/jpeg", "image/png", "image/webp"]
      .includes(ref.mime_type) &&
    typeof ref.data === "string" &&
    ref.data.length <= 8000000 &&
    /^[A-Za-z0-9+/]*={0,2}$/.test(ref.data)
  );
}

async function kiraRequest(endpoint, body) {
  if (!API_KEY) {
    throw new Error("KIRA_API_KEY تنظیم نشده است");
  }

  const response = await fetch(
    KIRA_BASE + endpoint,
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(120000)
    }
  );

  if (!response.ok) {
    const error = new Error(
      "خطا در ارتباط با Kira AI"
    );

    error.status = response.status;
    throw error;
  }

  return response;
}

// ===================================
// Basic Rate Limiting
// ===================================

const limits = new Map();

function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const key = `${req.user.id}:${req.path}`;
    const now = Date.now();

    let record = limits.get(key);

    if (!record || now >= record.reset) {
      record = {
        count: 0,
        reset: now + windowMs
      };
    }

    if (record.count >= max) {
      return res.status(429).json({
        error: "درخواست‌های شما زیاد است. کمی بعد تلاش کنید."
      });
    }

    record.count++;
    limits.set(key, record);

    next();
  };
}

setInterval(() => {
  const now = Date.now();

  for (const [key, record] of limits) {
    if (record.reset <= now) {
      limits.delete(key);
    }
  }
}, 60000).unref();

// ===================================
// Register
// ===================================

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!validateUsername(username)) {
      return res.status(400).json({
        error: "نام کاربری باید ۳ تا ۳۰ کاراکتر انگلیسی، عدد یا زیرخط باشد."
      });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        error: "رمز عبور باید بین ۸ تا ۱۲۸ کاراکتر باشد."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, password_hash)
       VALUES ($1, $2)
       RETURNING id, username`,
      [username, hash]
    );

    const user = result.rows[0];

    setLoginCookie(res, user);

    res.json({
      success: true,
      user
    });

  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "این نام کاربری قبلاً ثبت شده است."
      });
    }

    console.error("Register error:", err.message);

    res.status(500).json({
      error: "خطا در ثبت‌نام."
    });
  }
});

// ===================================
// Login
// ===================================

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (
      !validateUsername(username) ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "اطلاعات ورود نامعتبر است."
      });
    }

    const result = await pool.query(
      `SELECT id, username, password_hash
       FROM users
       WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است."
      });
    }

    setLoginCookie(res, user);

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (err) {
    console.error("Login error:", err.message);

    res.status(500).json({
      error: "خطا در ورود."
    });
  }
});

// ===================================
// Session
// ===================================

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: req.user
  });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("mmkk_session", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax"
  });

  res.json({
    success: true
  });
});

// ===================================
// Chat AI
// ===================================

app.post(
  "/api/chat",
  auth,
  rateLimit(20, 60000),
  async (req, res) => {
    try {
      const { message } = req.body;

      if (!validatePrompt(message)) {
        return res.status(400).json({
          error: "پیام معتبر نیست."
        });
      }

      const aiResponse = await kiraRequest(
        "/chat/completions",
        {
          model: "kira-mini-1.0",
          messages: [
            {
              role: "system",
              content:
                "You are MMKK AI, a multilingual assistant. " +
                "Reply in the user's language. " +
                "Help users with technology, VPN configuration, " +
                "internet troubleshooting, education, " +
                "programming and general questions."
            },
            {
              role: "user",
              content: message
            }
          ]
        }
      );

      const data = await aiResponse.json();

      const reply =
        data.choices?.[0]?.message?.content ||
        "پاسخی دریافت نشد.";

      const conversation = await pool.query(
        `INSERT INTO conversations
         (user_id, title)
         VALUES ($1, $2)
         RETURNING id`,
        [
          req.user.id,
          message.slice(0, 60)
        ]
      );

      const conversationId = conversation.rows[0].id;

      await pool.query(
        `INSERT INTO messages
         (conversation_id, role, content)
         VALUES
         ($1, 'user', $2),
         ($1, 'assistant', $3)`,
        [conversationId, message, reply]
      );

      res.json({
        reply,
        conversation_id: conversationId
      });

    } catch (err) {
      console.error("Chat error:", err.message);

      res.status(502).json({
        error: "خطا در پاسخ هوش مصنوعی."
      });
    }
  }
);

// ===================================
// Chat History
// ===================================

app.get("/api/history", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.title, c.created_at,
              m.role, m.content
       FROM conversations c
       LEFT JOIN messages m
         ON m.conversation_id = c.id
       WHERE c.user_id = $1
       ORDER BY c.created_at DESC, m.id ASC
       LIMIT 200`,
      [req.user.id]
    );

    res.json({
      history: result.rows
    });

  } catch (err) {
    res.status(500).json({
      error: "خطا در دریافت تاریخچه."
    });
  }
});

// ===================================
// Image Generation & Editing
// ===================================

app.post(
  "/api/image",
  auth,
  rateLimit(3, 60000),
  async (req, res) => {
    try {
      const {
        prompt,
        aspect_ratio,
        reference_images
      } = req.body;

      if (
        !validatePrompt(prompt) ||
        !validateReferences(reference_images)
      ) {
        return res.status(400).json({
          error: "اطلاعات تصویر نامعتبر است."
        });
      }

      const allowed = [
        "1:1", "16:9", "9:16", "4:3", "3:4"
      ];

      const ratio = allowed.includes(aspect_ratio)
        ? aspect_ratio
        : "1:1";

      const response = await kiraRequest(
        "/images/generations",
        {
          model: "kira-3.0-image",
          prompt,
          aspect_ratio: ratio,
          ...(reference_images
            ? { reference_images }
            : {})
        }
      );

      res.json(await response.json());

    } catch (err) {
      console.error("Image error:", err.message);

      res.status(502).json({
        error: "ساخت تصویر انجام نشد. اعتبار و دسترسی API را بررسی کنید."
      });
    }
  }
);

// ===================================
// Video Generation
// ===================================

app.post(
  "/api/video",
  auth,
  rateLimit(2, 600000),
  async (req, res) => {
    try {
      const {
        prompt,
        aspect_ratio,
        reference_images
      } = req.body;

      if (
        !validatePrompt(prompt) ||
        !validateReferences(reference_images)
      ) {
        return res.status(400).json({
          error: "اطلاعات ویدیو نامعتبر است."
        });
      }

      const allowed = ["16:9", "9:16", "1:1"];

      const ratio = allowed.includes(aspect_ratio)
        ? aspect_ratio
        : "16:9";

      const response = await kiraRequest(
        "/videos/generations",
        {
          model: "kira-3.0-video-flash",
          prompt,
          aspect_ratio: ratio,
          duration_seconds: 6,
          ...(reference_images
            ? { reference_images }
            : {})
        }
      );

      res.json(await response.json());

    } catch (err) {
      console.error("Video error:", err.message);

      res.status(502).json({
        error: "شروع ساخت ویدیو ناموفق بود."
      });
    }
  }
);

// ===================================
// Video Status
// ===================================

app.get(
  "/api/video/:id",
  auth,
  rateLimit(12, 60000),
  async (req, res) => {
    try {
      const id = req.params.id;

      if (!/^[a-zA-Z0-9-]{1,100}$/.test(id)) {
        return res.status(400).json({
          error: "شناسه ویدیو نامعتبر است."
        });
      }

      const response = await fetch(
        `${KIRA_BASE}/videos/operations/${id}`,
        {
          headers: {
            Authorization: `Bearer ${API_KEY}`
          },
          signal: AbortSignal.timeout(30000)
        }
      );

      if (!response.ok) {
        return res.status(502).json({
          error: "خطا در بررسی وضعیت ویدیو."
        });
      }

      res.json(await response.json());

    } catch (err) {
      res.status(502).json({
        error: "بررسی وضعیت ویدیو انجام نشد."
      });
    }
  }
);

// ===================================
// Text To Speech
// ===================================

app.post(
  "/api/speech",
  auth,
  rateLimit(5, 60000),
  async (req, res) => {
    try {
      const { text, voice } = req.body;

      if (
        typeof text !== "string" ||
        !text.trim() ||
        text.length > 3000
      ) {
        return res.status(400).json({
          error: "متن صدا نامعتبر است."
        });
      }

      const voices = [
        "alloy", "echo", "fable",
        "onyx", "nova", "shimmer"
      ];

      const selectedVoice = voices.includes(voice)
        ? voice
        : "alloy";

      const response = await kiraRequest(
        "/audio/speech",
        {
          model: "kira-3.0-flash-tts",
          input: text,
          voice: selectedVoice
        }
      );

      res.setHeader(
        "Content-Type",
        "audio/mpeg"
      );

      res.send(
        Buffer.from(await response.arrayBuffer())
      );

    } catch (err) {
      console.error("Speech error:", err.message);

      res.status(502).json({
        error: "ساخت صدا انجام نشد."
      });
    }
  }
);

// ===================================
// Start Server
// ===================================

async function start() {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
      "JWT_SECRET باید حداقل ۳۲ کاراکتر باشد."
    );
  }

  if (!API_KEY) {
    throw new Error(
      "KIRA_API_KEY تنظیم نشده است."
    );
  }

  await initDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `MMKK AI running on port ${PORT}`
    );
  });
}

start().catch(err => {
  console.error("Startup error:", err.message);
  process.exit(1);
});
