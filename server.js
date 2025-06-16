const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs-extra');
const path = require('path');
require('dotenv').config();
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bodyParser = require('body-parser');
const jwt = require("jsonwebtoken");
const users = {};
const getUserById = id => users[id];
const getUserByEmail = email => Object.values(users).find(u => u.email === email);
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
const createUser = (email) => {
  const id = Date.now().toString();
  users[id] = { id, email, plan: 'Free', createdAt: new Date() };
  return users[id];
};
const app = express();
// ✅ Serve static files from /public after app is defined
const PUBLIC_DIR = path.join(__dirname, "public");
app.use(express.static(PUBLIC_DIR));

app.use(cors({
  origin: "chrome-extension://hokannacimkcchppkaelkcjpeeamgjjp",
  credentials: true
}));

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY); // Add near top with other imports

// ✅ Stripe webhook route MUST use raw body parser
app.post("/webhook", bodyParser.raw({ type: "application/json" }), (req, res) => {
  console.log("📥 Webhook received");

  const sig = req.headers["stripe-signature"];

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    console.log("✅ Webhook verified:", event.type);
  } catch (err) {
    console.error("❌ Webhook signature verification failed:", err.message);
    return res.sendStatus(400);
  }

  // ✅ Handle checkout completion
let email = null;
let plan = "Free";
let user = null;

if (event.type === "checkout.session.completed") {
  const session = event.data.object;

  email = session.customer_email;
  plan = session.metadata?.plan || "Free";
  if (plan.toLowerCase() === "starter") plan = "Starter";
  else if (plan.toLowerCase() === "pro") plan = "Pro";
  else plan = "Free";

  console.log(`✅ Plan updated via webhook: ${email} → ${plan}`);
  updateUserPlan(email, plan);

  user = getUserByEmail(email);
  if (user) {
    user.plan = plan;
    console.log("🧠 Updated user memory object:", user);
  }
}

if (!user && email) {
  console.warn(`⚠️ User not found in memory when applying plan update: ${email}`);
}


  res.sendStatus(200);
});

const userPlans = {};

function updateUserPlan(email, plan) {
  if (email) {
    userPlans[email] = plan;
  }
}

app.get("/api/user/plan", (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ error: "Missing email" });

  const user = getUserByEmail(email);
  const plan = user?.plan || userPlans[email] || "Free";
  res.json({ plan });
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key',
  resave: false,
  saveUninitialized: false
}));


app.use(passport.initialize());
app.use(passport.session());

app.post("/create-checkout-session", async (req, res) => {
  const { email, plan } = req.body;

  const priceMap = {
    starter: "price_1RZjpSI3Juc0DFOS1WglYGkr",
    pro: "price_1RZjplI3Juc0DFOS2Kdrn2fB"
  };

  const priceId = priceMap[plan];

  if (!email || !priceId) {
    return res.status(400).json({ error: "Missing email or invalid plan." });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      customer_email: email,
      line_items: [{ price: priceId, quantity: 1 }],
      mode: "subscription",
      metadata: { plan },
      success_url: "https://chrome.google.com/webstore/detail/your-extension-id",
      cancel_url: "https://mailmind.ai/cancel", // You can update this later
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("Stripe Checkout error:", err);
    res.status(500).json({ error: "Failed to create Stripe session." });
  }
});


passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://mailmind-backend.onrender.com/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    console.log("🔍 Google profile received:", JSON.stringify(profile, null, 2));

    const email = profile.emails?.[0]?.value;
    if (!email) throw new Error("No email returned from Google");

    console.log("✅ Email extracted:", email);

    let user = getUserByEmail(email);
    if (!user) {
      console.log("🆕 Creating new user...");
      user = createUser(email);
    }

    console.log("✅ Authenticated user:", user);
    return done(null, user);
  } catch (err) {
    console.error("❌ Google login error:", err);
    return done(err);
  }
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

app.get("/api/auth/google", passport.authenticate("google", {
  scope: ["email", "profile"],
  accessType: "offline",
  prompt: "consent"
}));

app.get("/api/auth/google/callback", (req, res, next) => {
  passport.authenticate("google", { session: false }, (err, user) => {
    if (err || !user) return res.redirect("/");

    // Create a JWT with the user info
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        plan: user.plan
      },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    // Redirect back to the extension with the token in the URL
    res.redirect(`https://mailmind-backend.onrender.com/redirect.html?token=${token}`);
  })(req, res, next);
});



app.get("/api/user/me", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    return res.json(user);
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
});


// === Start Server ===
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ MailMind proxy & logger running on http://localhost:${PORT}`);
});

