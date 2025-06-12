const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs-extra');
const path = require('path');
require('dotenv').config();
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const users = {};
const getUserById = id => users[id];
const getUserByEmail = email => Object.values(users).find(u => u.email === email);
const createUser = (email) => {
  const id = Date.now().toString();
  users[id] = { id, email, plan: 'Free', createdAt: new Date() };
  return users[id];
};


const app = express();
app.use(cors());
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set true if behind HTTPS proxy
}));

app.use(passport.initialize());
app.use(passport.session());


passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  const email = profile.emails[0].value;
  let user = getUserByEmail(email);
  if (!user) user = createUser(email);
  return done(null, user);
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = getUserById(id);
  done(null, user || false);
});


// === OpenAI Proxy Route ===
app.post('/api/chat', async (req, res) => {
  const { messages, model = 'gpt-4o' } = req.body;

  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model,
        messages,
        temperature: 0.7,
        max_tokens: 300,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('❌ OpenAI API error:', error.response?.data || error.message);
    res.status(500).json({ error: 'OpenAI request failed' });
  }
});

// === Feedback Logging Route ===
const LOG_PATH = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_PATH, 'activity.log');
fs.ensureDirSync(LOG_PATH);

app.post('/api/log', async (req, res) => {
  const logEntry = {
    ...req.body,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  };

  const line = JSON.stringify(logEntry) + '\n';

  try {
    await fs.appendFile(LOG_FILE, line);
    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Failed to write log:', err);
    res.sendStatus(500);
  }
});

app.get("/api/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get("/api/auth/google/callback", 
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Redirect back to extension or frontend (use your actual extension ID)
    res.redirect("chrome-extension://<YOUR_EXTENSION_ID>/popup.html");
  }
);

app.get("/api/user/me", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Not logged in" });
  res.json(req.user);
});

// === Start Server ===
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ MailMind proxy & logger running on http://localhost:${PORT}`);
});
