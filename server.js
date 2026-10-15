const express = require("express");
const path = require("path");

const app = express();

app.use(express.json({ limit: "15mb" }));

app.use(express.static(path.join(__dirname, "public")));

const API_KEY = process.env.KIRA_API_KEY;

app.post("/api/chat", async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(503).json({
        error: "API Key تنظیم نشده است."
      });
    }

    const { message } = req.body;

    if (typeof message !== "string" ||
        !message.trim() ||
        message.length > 4000) {
      return res.status(400).json({
        error: "پیام معتبر نیست."
      });
    }

    const response = await fetch(
      "https://kiraai.vn/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: "kira-mini-1.0",
          messages: [
            {
              role: "system",
              content:
                "You are MMKK AI. Answer users in their preferred language. Help with technology, VPN configurations, education and general questions."
            },
            {
              role: "user",
              content: message
            }
          ]
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(502).json({
        error: "خطا در ارتباط با هوش مصنوعی."
      });
    }

    res.json({
      reply: data.choices?.[0]?.message?.content ||
        "پاسخی دریافت نشد."
    });

  } catch (error) {
    res.status(500).json({
      error: "خطای سرور."
    });
  }
});

app.get("/", (req, res) => {
  res.send("MMKK AI Server is running!");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MMKK AI running on port ${PORT}`);
});
