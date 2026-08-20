require('dotenv').config();
const express = require('express');
const session = require('express-session');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fetch = require('node-fetch');
const { Client, GatewayIntentBits } = require('discord.js');
const CBScript = require('./cbscript');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

/* ======================================================================== */
/* DATABASE                                                                 */
/* ======================================================================== */
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT UNIQUE,
    username TEXT,
    avatar TEXT,
    access_token TEXT,
    refresh_token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    token TEXT,
    avatar TEXT,
    banner TEXT,
    status TEXT DEFAULT 'offline',
    hosting_expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id INTEGER,
    name TEXT,
    trigger_type TEXT DEFAULT 'command',
    trigger_value TEXT,
    code TEXT,
    compiled_js TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS variables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id INTEGER,
    name TEXT UNIQUE,
    default_value TEXT,
    current_value TEXT,
    scope TEXT DEFAULT 'global',
    FOREIGN KEY (bot_id) REFERENCES bots(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS console_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id INTEGER,
    type TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

/* ======================================================================== */
/* MIDDLEWARE                                                               */
/* ======================================================================== */
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'dist')));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

/* ======================================================================== */
/* DISCORD OAUTH2                                                           */
/* ======================================================================== */
app.get('/api/auth/discord', (req, res) => {
  const url = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
  res.redirect(url);
});

app.get('/api/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.DISCORD_REDIRECT_URI
      })
    });
    const tokenData = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();

    db.get('SELECT * FROM users WHERE discord_id = ?', [userData.id], (err, row) => {
      const done = (userId) => {
        req.session.userId = userId;
        res.redirect('/');
      };

      if (row) {
        db.run('UPDATE users SET access_token=?, refresh_token=?, username=?, avatar=? WHERE id=?',
          [tokenData.access_token, tokenData.refresh_token, userData.username, userData.avatar, row.id],
          () => done(row.id)
        );
      } else {
        db.run('INSERT INTO users (discord_id, username, avatar, access_token, refresh_token) VALUES (?,?,?,?,?)',
          [userData.id, userData.username, userData.avatar, tokenData.access_token, tokenData.refresh_token],
          function () { done(this.lastID); }
        );
      }
    });
  } catch (e) {
    res.status(500).send('Authentication failed');
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  db.get('SELECT id, discord_id, username, avatar FROM users WHERE id = ?', [req.session.userId], (err, row) => {
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

/* ======================================================================== */
/* BOT CRUD                                                                 */
/* ======================================================================== */
app.get('/api/bots', requireAuth, (req, res) => {
  db.all('SELECT * FROM bots WHERE user_id = ? ORDER BY created_at DESC', [req.session.userId], (err, rows) => {
    res.json(rows || []);
  });
});

app.post('/api/bots', requireAuth, async (req, res) => {
  const { name, token } = req.body;
  try {
    const dRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bot ${token}` }
    });
    const botUser = await dRes.json();
    if (!botUser.id) return res.status(400).json({ error: 'Invalid bot token' });

    db.run('INSERT INTO bots (user_id, name, token, avatar) VALUES (?,?,?,?)',
      [req.session.userId, name || botUser.username, token, botUser.avatar],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, name: name || botUser.username, avatar: botUser.avatar, status: 'offline' });
      }
    );
  } catch (e) {
    res.status(400).json({ error: 'Discord API rejected token' });
  }
});

app.get('/api/bots/:id', requireAuth, (req, res) => {
  db.get('SELECT * FROM bots WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId], (err, row) => {
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

app.put('/api/bots/:id', requireAuth, (req, res) => {
  const { name, token } = req.body;
  db.run('UPDATE bots SET name = ?, token = ? WHERE id = ? AND user_id = ?',
    [name, token, req.params.id, req.session.userId],
    function () { res.json({ updated: this.changes }); }
  );
});

app.delete('/api/bots/:id', requireAuth, (req, res) => {
  botManager.stopBot(req.params.id);
  db.run('DELETE FROM bots WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId], () => {
    res.json({ deleted: true });
  });
});

app.post('/api/bots/:id/start', requireAuth, (req, res) => {
  db.get('SELECT * FROM bots WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId], async (err, bot) => {
    if (!bot) return res.status(404).json({ error: 'Not found' });
    if (bot.hosting_expires_at && new Date(bot.hosting_expires_at) < new Date()) {
      return res.status(403).json({ error: 'Hosting expired. Watch an ad to extend.' });
    }
    try {
      await botManager.startBot(bot.id, bot.token);
      res.json({ status: 'online' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
});

app.post('/api/bots/:id/stop', requireAuth, (req, res) => {
  botManager.stopBot(req.params.id);
  res.json({ status: 'offline' });
});

app.post('/api/bots/:id/hosting', requireAuth, (req, res) => {
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.run('UPDATE bots SET hosting_expires_at = ? WHERE id = ? AND user_id = ?',
    [expires, req.params.id, req.session.userId],
    () => res.json({ hosting_expires_at: expires })
  );
});

app.get('/api/bots/:
