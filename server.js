// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const basicAuth = require('basic-auth');

require('dotenv').config();

const PORT = process.env.PORT || 3000;
const MESSAGES_FILE = path.join(__dirname, 'messages.ndjson'); // newline-delimited encrypted JSON records
const SECRET = process.env.SECRET || 'change-this-to-a-strong-secret';
const VIEW_USER = process.env.VIEW_USER || 'admin';
const VIEW_PASS = process.env.VIEW_PASS || 'change-this-password';

// Optional Twilio: set TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM, NOTIFY_TO in env to get SMS notifications.
let twilioClient = null;
if (process.env.TWILIO_SID && process.env.TWILIO_TOKEN) {
  const Twilio = require('twilio');
  twilioClient = new Twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
}

const app = express();
app.use(helmet());
app.use(express.json({ limit: '2kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Basic rate limiter to reduce spam
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 6, // max 6 submissions per IP per minute
  message: { ok: false, error: 'Too many requests — slow down.' }
});
app.use('/api/send', limiter);

// encryption helpers
function deriveKey(secret) {
  // scrypt is good for deriving a key
  return crypto.scryptSync(secret, 'unique-salt-v1', 32);
}

function encryptRecord(obj) {
  const key = deriveKey(SECRET);
  const iv = crypto.randomBytes(12); // 96-bit recommended for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ct: ciphertext.toString('hex'),
    ts: new Date().toISOString()
  };
}

function decryptRecord(record) {
  try {
    const key = deriveKey(SECRET);
    const iv = Buffer.from(record.iv, 'hex');
    const tag = Buffer.from(record.tag, 'hex');
    const ct = Buffer.from(record.ct, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(plain.toString('utf8'));
  } catch (e) {
    return { error: 'decryption_failed' };
  }
}

// append encrypted record to file (ndjson)
function appendEncrypted(obj) {
  const rec = encryptRecord(obj);
  fs.appendFileSync(MESSAGES_FILE, JSON.stringify(rec) + '\n', { encoding: 'utf8', mode: 0o600 });
}

// public API: receive message
app.post('/api/send', (req, res) => {
  const { message, name } = req.body || {};
  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ ok: false, error: 'Message is required.' });
  }
  if (message.length > 1000) {
    return res.status(400).json({ ok: false, error: 'Message too long (max 1000 chars).' });
  }
  // Keep it anonymous: DO NOT store IP or other identifiers.
  const payload = {
    name: (name && String(name).slice(0, 60)) || '',
    message: message.slice(0, 1000)
  };

  try {
    appendEncrypted(payload);

    // optional: send SMS notification if Twilio env vars set
    if (twilioClient && process.env.NOTIFY_TO && process.env.TWILIO_FROM) {
      const notifyTo = process.env.NOTIFY_TO;
      const from = process.env.TWILIO_FROM;
      const preview = payload.message.length > 160 ? payload.message.slice(0,157) + '...' : payload.message;
      twilioClient.messages.create({
        to: notifyTo,
        from,
        body: `New anonymous message: "${preview}"`
      }).catch(err => {
        console.warn('Twilio notify failed:', err && err.message);
      });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('save error', err);
    return res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

// Basic-auth middleware for admin paths
function requireAdmin(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== VIEW_USER || user.pass !== VIEW_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="Private messages"');
    return res.status(401).send('Authentication required.');
  }
  next();
}

// admin: view messages (simple HTML)
app.get('/admin/messages', requireAdmin, (req, res) => {
  let lines = [];
  try {
    if (fs.existsSync(MESSAGES_FILE)) {
      const raw = fs.readFileSync(MESSAGES_FILE, 'utf8').trim().split('\n').filter(Boolean);
      lines = raw.map(l => {
        try { return JSON.parse(l); } catch (e) { return null; }
      }).filter(Boolean).reverse(); // newest first
    }
  } catch (err) {
    console.error('read failed', err);
  }

  const decrypted = lines.map(r => {
    const orig = decryptRecord(r);
    return {
      ts: r.ts || '',
      name: orig && orig.name ? orig.name : '',
      message: orig && orig.message ? orig.message : '[decryption failed]'
    };
  });

  // render a simple HTML table
  const rows = decrypted.map(d => `
    <tr>
      <td style="padding:8px; vertical-align:top; border-bottom:1px solid #eee">${d.ts}</td>
      <td style="padding:8px; vertical-align:top; border-bottom:1px solid #eee">${escapeHtml(d.name)}</td>
      <td style="padding:8px; vertical-align:top; border-bottom:1px solid #eee; white-space:pre-wrap">${escapeHtml(d.message)}</td>
    </tr>
  `).join('\n');

  res.send(`<!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <title>Your anonymous messages</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <style>body{font-family:system-ui, -apple-system, Roboto, Arial; padding:16px; background:#f5f6fb} table{width:100%; border-collapse:collapse; background:#fff; border-radius:10px; overflow:hidden} th,td{text-align:left} th{background:#f1f5ff; padding:10px; } .top{max-width:1100px;margin:0 auto}</style>
  </head>
  <body>
    <div class="top">
      <h1>Your anonymous messages</h1>
      <p>Protected by basic auth. To download as JSON, use <a href="/admin/download">Download JSON</a>.</p>
      <table>
        <thead><tr><th style="width:190px">Received</th><th style="width:140px">Nickname</th><th>Message</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p style="margin-top:12px; color:#666">Make sure to keep this page safe and use HTTPS when deployed.</p>
    </div>
  </body>
  </html>`);
});

// admin JSON download
app.get('/admin/download', requireAdmin, (req, res) => {
  try {
    if (!fs.existsSync(MESSAGES_FILE)) return res.json([]);
    const raw = fs.readFileSync(MESSAGES_FILE, 'utf8').trim().split('\n').filter(Boolean);
    const out = raw.map(l => {
      try {
        const r = JSON.parse(l);
        const d = decryptRecord(r);
        return { ts: r.ts, ...d };
      } catch (e) {
        return null;
      }
    }).filter(Boolean);
    res.setHeader('Content-Disposition', 'attachment; filename="messages.json"');
    res.json(out);
  } catch (err) {
    console.error('download failed', err);
    res.status(500).json({ ok: false });
  }
});

function escapeHtml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}.`);
  console.log(`Admin user: ${VIEW_USER} — protect the password (VIEW_PASS).`);
});
