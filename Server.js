require('dotenv').config();
const express = require('express');
const session = require('express-session');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fetch = require('node-fetch');
const { Client, GatewayIntentBits } = require('discord.js');
const { spawn } = require('child_process');
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
    language TEXT DEFAULT 'cbscript',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS variables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id INTEGER,
    name TEXT,
    default_value TEXT,
    current_value TEXT,
    scope TEXT DEFAULT 'global'
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
/* LANGUAGE DETECTION (mirrors frontend logic)                                */
/* ======================================================================== */
function detectLanguage(code) {
  if (!code || !code.trim()) return 'cbscript';
  const c = code.trim();
  if (/<\s*nif\b/i.test(c)) return 'cbscript';
  if (/^\s*(def |class |import |from |print\(|if __name__\s*==)/m.test(c)) return 'python';
  if (/^\s*(function|const |let |var |=>|console\.|require\(|module\.|export |import .*from)/m.test(c)) return 'javascript';
  const pyScore = (c.match(/:\s*$/gm) || []).length + (c.match(/^\s{2,}\w+/gm) || []).length;
  const jsScore = (c.match(/[{};]\s*$/gm) || []).length + (c.match(/const |let |var /g) || []).length;
  if (pyScore > jsScore) return 'python';
  if (jsScore > pyScore) return 'javascript';
  return 'cbscript';
}

function wrapJS(code) {
  return `(async function(runtime) {\n  try {\n${code.split('\n').map(l => '    ' + l).join('\n')}\n  } catch(e) { runtime.console.error(e.message); }\n})`;
}

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
      const done = (userId) => { req.session.userId = userId; res.redirect('/'); };
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
  db.all('SELECT * FROM bots WHERE user_id = ? ORDER BY created_at DESC', [req.session.userId], (err, rows) => res.json(rows || []));
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

/* ======================================================================== */
/* SCRIPTS                                                                  */
/* ======================================================================== */
app.get('/api/bots/:id/scripts', requireAuth, (req, res) => {
  db.all('SELECT * FROM scripts WHERE bot_id = ?', [req.params.id], (err, rows) => res.json(rows || []));
});

app.post('/api/bots/:id/scripts', requireAuth, (req, res) => {
  const { name, trigger_type, trigger_value, code } = req.body;
  const language = detectLanguage(code);
  let compiled_js = null;
  if (language === 'cbscript') {
    compiled_js = CBScript.compile(code).js;
  } else if (language === 'javascript') {
    compiled_js = wrapJS(code);
  } else {
    compiled_js = code; // Python stored raw
  }
  db.run('INSERT INTO scripts (bot_id, name, trigger_type, trigger_value, code, compiled_js, language) VALUES (?,?,?,?,?,?,?)',
    [req.params.id, name, trigger_type, trigger_value, code, compiled_js, language],
    function () { res.json({ id: this.lastID, language }); }
  );
});

app.put('/api/bots/:id/scripts/:sid', requireAuth, (req, res) => {
  const { name, trigger_type, trigger_value, code } = req.body;
  const language = detectLanguage(code);
  let compiled_js = null;
  if (language === 'cbscript') {
    compiled_js = CBScript.compile(code).js;
  } else if (language === 'javascript') {
    compiled_js = wrapJS(code);
  } else {
    compiled_js = code;
  }
  db.run('UPDATE scripts SET name=?, trigger_type=?, trigger_value=?, code=?, compiled_js=?, language=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND bot_id=?',
    [name, trigger_type, trigger_value, code, compiled_js, language, req.params.sid, req.params.id],
    () => res.json({ ok: true, language })
  );
});

/* ======================================================================== */
/* VARIABLES                                                                */
/* ======================================================================== */
app.get('/api/bots/:id/variables', requireAuth, (req, res) => {
  db.all('SELECT * FROM variables WHERE bot_id = ?', [req.params.id], (err, rows) => res.json(rows || []));
});

app.post('/api/bots/:id/variables', requireAuth, (req, res) => {
  const { name, default_value, scope } = req.body;
  db.run('INSERT INTO variables (bot_id, name, default_value, current_value, scope) VALUES (?,?,?,?,?)',
    [req.params.id, name, default_value, default_value, scope],
    function () { res.json({ id: this.lastID }); }
  );
});

/* ======================================================================== */
/* BOT RUNTIME & MANAGER                                                    */
/* ======================================================================== */
const activeBots = new Map();

function broadcastLog(botId, type, message) {
  io.to(`bot_${botId}`).emit('console', { type, message, time: Date.now() });
  db.run('INSERT INTO console_logs (bot_id, type, message) VALUES (?,?,?)', [botId, type, message]);
}

function createRuntime(client, message, botId) {
  return {
    client, message, channel: message.channel, args: message.content.split(' ').slice(1),
    vars: new Map(), userVars: new Map(), guildVars: new Map(),
    _embed: null, _json: {},
    console: {
      log: (msg) => broadcastLog(botId, 'log', String(msg)),
      error: (msg) => broadcastLog(botId, 'err', String(msg)),
      warn: (msg) => broadcastLog(botId, 'warn', String(msg))
    },
    ownerId: process.env.DISCORD_CLIENT_ID
  };
}

async function runPythonScript(code, runtime) {
  return new Promise((resolve, reject) => {
    const ctx = JSON.stringify({
      message: { content: runtime.message.content, author: { id: runtime.message.author.id, username: runtime.message.author.username } },
      channel: { id: runtime.channel.id, name: runtime.channel.name || null },
      args: runtime.args
    });
    const wrapper = `import json, sys\nctx = json.loads(sys.argv[1])\n${code}\n`;
    const py = spawn('python3', ['-c', wrapper, ctx], { timeout: 5000 });
    let out = '', err = '';
    py.stdout.on('data', d => out += d.toString());
    py.stderr.on('data', d => { err += d.toString(); runtime.console.error(d.toString()); });
    py.on('close', (code) => {
      if (out) runtime.console.log(out);
      resolve(out);
    });
    py.on('error', (e) => {
      runtime.console.error('Python not installed or failed: ' + e.message);
      resolve('');
    });
  });
}

const botManager = {
  async startBot(botId, token) {
    if (activeBots.has(botId)) return;
    const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });
    
    client.on('ready', () => {
      db.run("UPDATE bots SET status = 'online' WHERE id = ?", [botId]);
      broadcastLog(botId, 'info', `Bot logged in as ${client.user.tag}`);
    });

    client.on('messageCreate', async (message) => {
      if (message.author.bot) return;
      db.all('SELECT * FROM scripts WHERE bot_id = ?', [botId], async (err, scripts) => {
        if (!scripts) return;
        for (const script of scripts) {
          const trigger = script.trigger_value || '';
          const type = script.trigger_type;
          let match = false;
          if (type === 'command' && message.content.startsWith(trigger)) match = true;
          if (type === 'slash' && message.content === trigger) match = true;
          if (type === 'event') match = true;

          if (match) {
            const runtime = createRuntime(client, message, botId);
            try {
              if (script.language === 'python') {
                await runPythonScript(script.code, runtime);
              } else {
                const fn = new Function('runtime', 'return (' + (script.compiled_js || '') + ')(runtime);');
                await fn(runtime);
              }
            } catch (e) {
              broadcastLog(botId, 'err', e.message);
            }
          }
        }
      });
    });

    await client.login(token);
    activeBots.set(botId, client);
  },

  stopBot(botId) {
    const client = activeBots.get(botId);
    if (client) { client.destroy(); activeBots.delete(botId); }
    db.run("UPDATE bots SET status = 'offline' WHERE id = ?", [botId]);
  }
};

/* ======================================================================== */
/* SOCKET.IO                                                                */
/* ======================================================================== */
io.on('connection', (socket) => {
  socket.on('join', (botId) => { socket.join(`bot_${botId}`); });
});

/* ======================================================================== */
/* START                                                                    */
/* ======================================================================== */
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
