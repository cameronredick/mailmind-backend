const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs-extra');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

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

// === Start Server ===
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✅ MailMind proxy & logger running on http://localhost:${PORT}`);
});
