/**
 * GayChat - Encrypted Group Messaging Server
 * Express + Socket.IO + SQLite backend
 */

'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');

// ── Constants ─────────────────────────────────────────────────────────────────
const MAX_ENCRYPTED_CONTENT_LENGTH = 34_000_000_000; // ~25GB + base64 overhead (25GB * 1.37)

// ── App & Server ──────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = new Server(server);

// ── Content Security Policy + HSTS ───────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' ws: wss:;"
  );
  // Only send HSTS over HTTPS (production / Railway)
  if (process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT != null) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  }
  next();
});

// ── Login brute-force protection ──────────────────────────────────────────────
// Track failed login attempts per IP. 10 failures within a 15-minute window
// locks the IP for the remainder of that window.
const LOGIN_ATTEMPT_WINDOW = 15 * 60 * 1000; // 15 minutes
const LOGIN_MAX_ATTEMPTS   = 10;
const loginAttempts = new Map(); // ip -> { count, windowStart }

// Periodically prune stale entries so the map doesn't grow unboundedly.
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts) {
    if (now - data.windowStart > LOGIN_ATTEMPT_WINDOW) loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000); // every 5 minutes

function recordFailedLogin(ip) {
  const now = Date.now();
  const data = loginAttempts.get(ip);
  if (!data || now - data.windowStart > LOGIN_ATTEMPT_WINDOW) {
    loginAttempts.set(ip, { count: 1, windowStart: now });
    return;
  }
  data.count++;
}

function isLoginBlocked(ip) {
  const now = Date.now();
  const data = loginAttempts.get(ip);
  if (!data) return false;
  if (now - data.windowStart > LOGIN_ATTEMPT_WINDOW) { loginAttempts.delete(ip); return false; }
  return data.count >= LOGIN_MAX_ATTEMPTS;
}

function clearLoginAttempts(ip) {
  loginAttempts.delete(ip);
}

// ── Database ──────────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || './gaychat.db';
const SESSIONS_DIR = process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : '.';

if (!process.env.DB_PATH) {
  console.warn('⚠️  WARNING: DB_PATH not set. Database is stored at ./gaychat.db on ephemeral filesystem. Data will be lost on redeploy. Set DB_PATH=/data/gaychat.db and mount a Railway Volume to persist data.');
}

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent performance
db.pragma('journal_mode = WAL');

// Create tables on startup
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    icon_color TEXT NOT NULL DEFAULT '#4A90D9',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS group_chats (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    created_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    iv TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Safe migrations — each wrapped in try/catch so re-runs are harmless
const migrations = [
  "ALTER TABLE messages ADD COLUMN type TEXT NOT NULL DEFAULT 'text'",
  "ALTER TABLE messages ADD COLUMN reply_to TEXT",
  "ALTER TABLE messages ADD COLUMN filename TEXT",
  "ALTER TABLE messages ADD COLUMN whisper_to TEXT",
  "ALTER TABLE group_chats ADD COLUMN allow_member_clear INTEGER NOT NULL DEFAULT 0",
  "CREATE TABLE IF NOT EXISTS _config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  "ALTER TABLE users ADD COLUMN profile_picture TEXT",
  "ALTER TABLE messages ADD COLUMN edited_at TEXT",
  // Composite index to support efficient pagination ORDER BY (created_at DESC, id DESC)
  "CREATE INDEX IF NOT EXISTS idx_messages_group_pagination ON messages (group_id, created_at DESC, id DESC)",
];
for (const sql of migrations) {
  try { db.exec(sql); } catch { /* column/table already exists */ }
}

// Ensure a stable session secret persists across restarts even without SESSION_SECRET env var
function getOrCreateSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  try {
    const existing = db.prepare("SELECT value FROM _config WHERE key = 'session_secret'").get();
    if (existing) return existing.value;
    const newSecret = crypto.randomBytes(32).toString('hex');
    db.prepare("INSERT INTO _config (key, value) VALUES ('session_secret', ?)").run(newSecret);
    return newSecret;
  } catch (err) {
    // Do NOT fall back to a predictable hard-coded string. Generate a random
    // ephemeral secret instead — existing sessions will be invalidated after
    // a restart but the server remains secure.
    console.error('getOrCreateSessionSecret error — using ephemeral random secret (sessions will not survive restart):', err);
    return crypto.randomBytes(32).toString('hex');
  }
}
const SESSION_SECRET = getOrCreateSessionSecret();

// ── Prepared Statements ───────────────────────────────────────────────────────
const stmts = {
  // Users
  findUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  findUserById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare(
    'INSERT INTO users (id, username, password_hash, icon_color) VALUES (?, ?, ?, ?)'
  ),
  updateUser: db.prepare(
    'UPDATE users SET username = COALESCE(?, username), icon_color = COALESCE(?, icon_color), profile_picture = COALESCE(?, profile_picture) WHERE id = ?'
  ),
  deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
  deleteUserMemberships: db.prepare('DELETE FROM group_members WHERE user_id = ?'),

  // Groups
  insertGroup: db.prepare(
    'INSERT INTO group_chats (id, name, code, created_by) VALUES (?, ?, ?, ?)'
  ),
  findGroupByCode: db.prepare('SELECT * FROM group_chats WHERE code = ?'),
  findGroupById: db.prepare('SELECT * FROM group_chats WHERE id = ?'),
  updateGroupName: db.prepare('UPDATE group_chats SET name = ? WHERE id = ?'),
  updateGroupAllowMemberClear: db.prepare('UPDATE group_chats SET allow_member_clear = ? WHERE id = ?'),

  // Members
  insertMember: db.prepare(
    'INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)'
  ),
  isMember: db.prepare(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?'
  ),
  getUserGroups: db.prepare(`
    SELECT g.id, g.name, g.code, g.created_by, g.created_at, g.allow_member_clear
    FROM group_chats g
    JOIN group_members gm ON g.id = gm.group_id
    WHERE gm.user_id = ?
    ORDER BY g.created_at DESC
  `),
  getGroupMembers: db.prepare(`
    SELECT u.id, u.username, u.icon_color, u.profile_picture
    FROM users u
    JOIN group_members gm ON u.id = gm.user_id
    WHERE gm.group_id = ?
    ORDER BY gm.joined_at ASC
  `),

  // Admin
  getAllUsers: db.prepare('SELECT id, username, icon_color, created_at FROM users ORDER BY created_at DESC'),

  // Messages — DESC then reverse for last-N-in-order pattern
  getLastMessages: db.prepare(`
    SELECT m.id, m.group_id, m.sender_id, u.username AS sender_name,
           u.icon_color AS sender_color, m.encrypted_content, m.iv,
           m.type, m.reply_to, m.filename, m.whisper_to, m.created_at, m.edited_at
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE m.group_id = ?
    ORDER BY m.created_at DESC, m.id DESC
    LIMIT ?
  `),
  getMessagesBefore: db.prepare(`
    WITH ref AS (SELECT created_at, id FROM messages WHERE id = ?)
    SELECT m.id, m.group_id, m.sender_id, u.username AS sender_name,
           u.icon_color AS sender_color, m.encrypted_content, m.iv,
           m.type, m.reply_to, m.filename, m.whisper_to, m.created_at, m.edited_at
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    CROSS JOIN ref
    WHERE m.group_id = ? AND (
      m.created_at < ref.created_at OR
      (m.created_at = ref.created_at AND m.id < ref.id)
    )
    ORDER BY m.created_at DESC, m.id DESC
    LIMIT ?
  `),
  insertMessage: db.prepare(
    'INSERT INTO messages (id, group_id, sender_id, encrypted_content, iv, type, reply_to, filename, whisper_to) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ),
  findMessageById: db.prepare('SELECT * FROM messages WHERE id = ?'),
  deleteMessage: db.prepare('DELETE FROM messages WHERE id = ?'),
  updateMessage: db.prepare(
    'UPDATE messages SET encrypted_content = ?, iv = ?, edited_at = ? WHERE id = ?'
  ),

  // Owner controls
  deleteMember: db.prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?'),
  deleteGroupMessages: db.prepare('DELETE FROM messages WHERE group_id = ?'),
  deleteGroupMembers: db.prepare('DELETE FROM group_members WHERE group_id = ?'),
  deleteGroup: db.prepare('DELETE FROM group_chats WHERE id = ?'),

  // Utility: all group IDs a user belongs to (for scoped broadcasts)
  getUserGroupIds: db.prepare('SELECT group_id FROM group_members WHERE user_id = ?'),
};

// ── Session Middleware ────────────────────────────────────────────────────────
const sessionMiddleware = session({
  store: new SQLiteStore({ db: 'sessions.db', dir: SESSIONS_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT != null,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  },
});

// ── Express Middleware ────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '30gb' }));
app.use(sessionMiddleware);

// ── CSRF Protection ───────────────────────────────────────────────────────────
// Double-submit token pattern: token stored in session, sent as X-CSRF-Token header.
// Login and register are intentionally exempt because no session exists before
// the first request, so a CSRF token cannot be pre-fetched. These endpoints are
// also protected by sameSite:'lax' cookies which prevent cross-origin POSTs from
// regular browsers. The /auth/me endpoint is GET-only so no CSRF risk.
function getCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

// Paths that don't require a CSRF token (see reasoning above)
const CSRF_EXEMPT = [
  '/auth/csrf',
  '/auth/register', // No session before first request; protected by sameSite:lax
  '/auth/login',    // No session before first request; protected by sameSite:lax
  '/auth/me',       // GET only
];

function csrfProtect(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (CSRF_EXEMPT.includes(req.path)) return next();

  const token = req.headers['x-csrf-token'];
  const sessionToken = req.session && req.session.csrfToken;

  const valid =
    token &&
    sessionToken &&
    token.length === sessionToken.length &&
    crypto.timingSafeEqual(Buffer.from(token), Buffer.from(sessionToken));

  if (!valid) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

app.use('/api', csrfProtect);

// ── Auth Middleware ───────────────────────────────────────────────────────────
const UNPROTECTED = [
  '/auth/register',
  '/auth/login',
  '/auth/me',
  '/auth/csrf',
];

function requireAuth(req, res, next) {
  if (UNPROTECTED.includes(req.path)) return next();
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

app.use('/api', requireAuth);

// ── Helper: format objects ────────────────────────────────────────────────────
function formatUser(user) {
  return { id: user.id, username: user.username, iconColor: user.icon_color, profilePicture: user.profile_picture || null };
}

function formatMessage(m) {
  return {
    id: m.id,
    groupId: m.group_id,
    senderId: m.sender_id,
    senderName: m.sender_name,
    senderColor: m.sender_color,
    encryptedContent: m.encrypted_content,
    iv: m.iv,
    type: m.type || 'text',
    replyTo: m.reply_to || null,
    filename: m.filename || null,
    whisperTo: m.whisper_to || null,
    createdAt: m.created_at,
    editedAt: m.edited_at || null,
  };
}

// ── Auth Routes ───────────────────────────────────────────────────────────────

app.get('/api/auth/csrf', (req, res) => {
  const token = getCsrfToken(req);
  req.session.save(() => res.json({ csrfToken: token }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const user = stmts.findUserById.get(req.session.userId);
  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json(formatUser(user));
});

app.post('/api/auth/register', async (req, res) => {
  const { username, password, iconColor } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (username.length < 2 || username.length > 32) {
    return res.status(400).json({ error: 'Username must be 2–32 characters' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const existing = stmts.findUserByUsername.get(username);
  if (existing) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const id = uuidv4();
    const color = iconColor || '#4A90D9';

    stmts.insertUser.run(id, username, passwordHash, color);

    req.session.userId = id;
    req.session.save(() => {
      const user = stmts.findUserById.get(id);
      res.status(201).json(formatUser(user));
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Brute-force protection: block IP after too many failed attempts
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  if (isLoginBlocked(clientIp)) {
    return res.status(429).json({ error: 'Too many failed login attempts. Please try again later.' });
  }

  const user = stmts.findUserByUsername.get(username);
  if (!user) {
    recordFailedLogin(clientIp);
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  try {
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      recordFailedLogin(clientIp);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    clearLoginAttempts(clientIp);
    req.session.userId = user.id;
    req.session.save(() => {
      res.json(formatUser(user));
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// PATCH /api/auth/profile — update username / iconColor / profilePicture
app.patch('/api/auth/profile', (req, res) => {
  const userId = req.session.userId;
  const { username, iconColor, profilePicture } = req.body;

  if (username !== undefined) {
    if (typeof username !== 'string' || username.length < 2 || username.length > 32) {
      return res.status(400).json({ error: 'Username must be 2–32 characters' });
    }
    const existing = stmts.findUserByUsername.get(username);
    if (existing && existing.id !== userId) {
      return res.status(409).json({ error: 'Username already taken' });
    }
  }

  if (profilePicture !== undefined && profilePicture !== null) {
    // Only allow safe raster image MIME types — reject SVG and other types
    // that could carry embedded scripts.
    const ALLOWED_PIC_PREFIXES = [
      'data:image/jpeg;base64,',
      'data:image/png;base64,',
      'data:image/gif;base64,',
      'data:image/webp;base64,',
    ];
    if (
      typeof profilePicture !== 'string' ||
      !ALLOWED_PIC_PREFIXES.some(p => profilePicture.startsWith(p))
    ) {
      return res.status(400).json({ error: 'Invalid profile picture format. Only JPEG, PNG, GIF, and WebP are allowed.' });
    }
    // Base64 encoded 2MB max
    if (profilePicture.length > 2 * 1024 * 1024 * 1.4) {
      return res.status(400).json({ error: 'Profile picture too large (max 2MB)' });
    }
  }

  try {
    stmts.updateUser.run(username || null, iconColor || null, profilePicture !== undefined ? profilePicture : null, userId);
    const user = stmts.findUserById.get(userId);
    // Update in-memory socket state for all connected sockets of this user
    for (const [, s] of io.sockets.sockets) {
      if (s.userId === userId) {
        s.username = user.username;
        s.iconColor = user.icon_color;
        s.profilePicture = user.profile_picture;
      }
    }
    // Emit user_updated only to rooms (groups) this user belongs to — not globally.
    // This prevents leaking profile data to users who share no groups with them.
    const userGroupIds = stmts.getUserGroupIds.all(userId).map(r => r.group_id);
    const payload = formatUser(user);
    for (const gid of userGroupIds) {
      io.to(gid).emit('user_updated', payload);
    }
    res.json(payload);
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/auth/account — delete account
const deleteAccountTx = db.transaction((userId) => {
  stmts.deleteUserMemberships.run(userId);
  stmts.deleteUser.run(userId);
});

app.delete('/api/auth/account', (req, res) => {
  const userId = req.session.userId;

  try {
    deleteAccountTx(userId);
    req.session.destroy(() => {
      res.json({ ok: true });
    });
  } catch (err) {
    console.error('Account delete error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Admin Routes ──────────────────────────────────────────────────────────────

app.get('/api/admin/users', (req, res) => {
  const secret = process.env.ADMIN_SECRET;
  if (!secret) {
    return res.status(503).json({ error: 'Admin endpoint disabled. Set ADMIN_SECRET environment variable to enable.' });
  }
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  // Use timing-safe comparison to prevent timing-based secret enumeration
  const secretBuf = Buffer.from(secret);
  const tokenBuf  = Buffer.from(token);
  const valid = token.length === secret.length &&
    crypto.timingSafeEqual(tokenBuf, secretBuf);
  if (!valid) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const users = stmts.getAllUsers.all();
  res.json(users.map(u => ({
    id: u.id,
    username: u.username,
    iconColor: u.icon_color,
    createdAt: u.created_at,
  })));
});

// ── Group Routes ──────────────────────────────────────────────────────────────

app.post('/api/groups/create', (req, res) => {
  const { name, code } = req.body;
  const userId = req.session.userId;

  if (!name || !code) {
    return res.status(400).json({ error: 'Group name and code are required' });
  }
  if (name.length < 1 || name.length > 64) {
    return res.status(400).json({ error: 'Group name must be 1–64 characters' });
  }
  if (code.length < 2 || code.length > 32) {
    return res.status(400).json({ error: 'Group code must be 2–32 characters' });
  }

  const existing = stmts.findGroupByCode.get(code);
  if (existing) {
    return res.status(409).json({ error: 'Group code already in use' });
  }

  const groupId = uuidv4();
  stmts.insertGroup.run(groupId, name, code, userId);
  stmts.insertMember.run(groupId, userId);

  const group = stmts.findGroupById.get(groupId);
  res.status(201).json({
    id: group.id,
    name: group.name,
    code: group.code,
    createdBy: group.created_by,
    allowMemberClear: group.allow_member_clear || 0,
  });
});

app.post('/api/groups/join', (req, res) => {
  const { code } = req.body;
  const userId = req.session.userId;

  if (!code) {
    return res.status(400).json({ error: 'Group code is required' });
  }

  const group = stmts.findGroupByCode.get(code);
  if (!group) {
    return res.status(404).json({ error: 'Group not found' });
  }

  stmts.insertMember.run(group.id, userId);

  // Emit member_joined to the group room
  const user = stmts.findUserById.get(userId);
  io.to(group.id).emit('member_joined', {
    userId,
    username: user.username,
    iconColor: user.icon_color,
    profilePicture: user.profile_picture || null,
    groupId: group.id,
  });

  res.json({
    id: group.id,
    name: group.name,
    code: group.code,
    createdBy: group.created_by,
    allowMemberClear: group.allow_member_clear || 0,
  });
});

app.get('/api/groups/mine', (req, res) => {
  const userId = req.session.userId;
  const groups = stmts.getUserGroups.all(userId);
  res.json(
    groups.map((g) => ({
      id: g.id,
      name: g.name,
      code: g.code,
      createdBy: g.created_by,
      allowMemberClear: g.allow_member_clear || 0,
    }))
  );
});

// PATCH /api/groups/:groupId/name — rename group (all members)
app.patch('/api/groups/:groupId/name', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;
  const { name } = req.body;

  const member = stmts.isMember.get(groupId, userId);
  if (!member) return res.status(403).json({ error: 'Not a member of this group' });

  if (!name || name.length < 1 || name.length > 64) {
    return res.status(400).json({ error: 'Group name must be 1–64 characters' });
  }

  stmts.updateGroupName.run(name, groupId);
  io.to(groupId).emit('group_renamed', { groupId, newName: name });
  res.json({ ok: true });
});

// PATCH /api/groups/:groupId/settings — update allow_member_clear (owner only)
app.patch('/api/groups/:groupId/settings', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;
  const { allowMemberClear } = req.body;

  const group = stmts.findGroupById.get(groupId);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (group.created_by !== userId) return res.status(403).json({ error: 'Only the group owner can change settings' });

  if (allowMemberClear !== undefined) {
    stmts.updateGroupAllowMemberClear.run(allowMemberClear ? 1 : 0, groupId);
  }
  res.json({ ok: true });
});

// GET /api/groups/:groupId/messages — paginated messages
app.get('/api/groups/:groupId/messages', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
  const before = req.query.before || null;

  const member = stmts.isMember.get(groupId, userId);
  if (!member) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }

  let rows;
  if (before) {
    // CTE parameter order: (refMessageId, groupId, limit)
    rows = stmts.getMessagesBefore.all(before, groupId, limit).reverse();
  } else {
    rows = stmts.getLastMessages.all(groupId, limit).reverse();
  }

  res.json(rows.map(formatMessage));
});

// DELETE /api/groups/:groupId/messages — clear all messages (owner, or members if allowed)
app.delete('/api/groups/:groupId/messages', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;

  const group = stmts.findGroupById.get(groupId);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  const member = stmts.isMember.get(groupId, userId);
  if (!member) return res.status(403).json({ error: 'Not a member of this group' });

  const isOwner = group.created_by === userId;
  if (!isOwner && !group.allow_member_clear) {
    return res.status(403).json({ error: 'Only the group owner can clear chat history' });
  }

  stmts.deleteGroupMessages.run(groupId);
  io.to(groupId).emit('chat_cleared', { groupId });
  res.json({ ok: true });
});

// DELETE /api/groups/:groupId/messages/:messageId — delete single message
app.delete('/api/groups/:groupId/messages/:messageId', (req, res) => {
  const { groupId, messageId } = req.params;
  const userId = req.session.userId;

  const member = stmts.isMember.get(groupId, userId);
  if (!member) return res.status(403).json({ error: 'Not a member of this group' });

  const message = stmts.findMessageById.get(messageId);
  if (!message || message.group_id !== groupId) {
    return res.status(404).json({ error: 'Message not found' });
  }

  const group = stmts.findGroupById.get(groupId);
  const isOwner = group && group.created_by === userId;
  const isSender = message.sender_id === userId;

  if (!isOwner && !isSender) {
    return res.status(403).json({ error: 'You can only delete your own messages' });
  }

  stmts.deleteMessage.run(messageId);
  io.to(groupId).emit('message_deleted', { messageId, groupId });
  res.json({ ok: true });
});

// PATCH /api/groups/:groupId/messages/:messageId — edit a message (sender only, text/whisper)
app.patch('/api/groups/:groupId/messages/:messageId', (req, res) => {
  const { groupId, messageId } = req.params;
  const userId = req.session.userId;
  const { encryptedContent, iv } = req.body;

  if (!encryptedContent || typeof encryptedContent !== 'string' || !iv || typeof iv !== 'string') {
    return res.status(400).json({ error: 'encryptedContent and iv are required' });
  }
  if (encryptedContent.length > MAX_ENCRYPTED_CONTENT_LENGTH) {
    return res.status(400).json({ error: 'Message too large.' });
  }

  const member = stmts.isMember.get(groupId, userId);
  if (!member) return res.status(403).json({ error: 'Not a member of this group' });

  const message = stmts.findMessageById.get(messageId);
  if (!message || message.group_id !== groupId) {
    return res.status(404).json({ error: 'Message not found' });
  }
  if (message.sender_id !== userId) {
    return res.status(403).json({ error: 'You can only edit your own messages' });
  }
  if (message.type !== 'text' && message.type !== 'whisper') {
    return res.status(400).json({ error: 'Only text messages can be edited' });
  }

  const editedAt = new Date().toISOString();
  stmts.updateMessage.run(encryptedContent, iv, editedAt, messageId);
  io.to(groupId).emit('message_edited', { messageId, groupId, encryptedContent, iv, editedAt });
  res.json({ ok: true });
});

// DELETE /api/groups/:groupId/leave — leave group (non-owner)
app.delete('/api/groups/:groupId/leave', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;

  const group = stmts.findGroupById.get(groupId);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  const member = stmts.isMember.get(groupId, userId);
  if (!member) return res.status(403).json({ error: 'Not a member of this group' });

  if (group.created_by === userId) {
    return res.status(400).json({ error: 'Group owner cannot leave. Disband the group instead.' });
  }

  stmts.deleteMember.run(groupId, userId);

  const user = stmts.findUserById.get(userId);
  io.to(groupId).emit('member_left', {
    userId,
    username: user ? user.username : 'Unknown',
    groupId,
  });

  res.json({ ok: true });
});

// GET /api/groups/:groupId/members — list group members
app.get('/api/groups/:groupId/members', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;

  const member = stmts.isMember.get(groupId, userId);
  if (!member) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }

  const members = stmts.getGroupMembers.all(groupId);
  res.json(
    members.map((u) => ({
      id: u.id,
      username: u.username,
      iconColor: u.icon_color,
      profilePicture: u.profile_picture || null,
    }))
  );
});

// POST /api/groups/:groupId/upload — upload encrypted file or image
app.post('/api/groups/:groupId/upload', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;

  const member = stmts.isMember.get(groupId, userId);
  if (!member) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }

  const { encryptedContent, iv, type, filename } = req.body;
  if (!encryptedContent || typeof encryptedContent !== 'string' || !iv || typeof iv !== 'string') {
    return res.status(400).json({ error: 'encryptedContent and iv are required' });
  }

  // Validate type
  const msgType = type === 'file' ? 'file' : 'image';

  // Sanitize filename: strip path separators and limit length
  let safeFilename = null;
  if (filename && typeof filename === 'string') {
    safeFilename = filename.replace(/[/\\]/g, '').slice(0, 255) || null;
  }

  // Enforce cap
  if (encryptedContent.length > MAX_ENCRYPTED_CONTENT_LENGTH) {
    return res.status(400).json({ error: 'File too large. Maximum size is 25GB.' });
  }
  const msgId = uuidv4();
  const createdAt = new Date().toISOString();
  const user = stmts.findUserById.get(userId);

  try {
    stmts.insertMessage.run(msgId, groupId, userId, encryptedContent, iv, msgType, null, safeFilename, null);
  } catch (err) {
    console.error('DB insert file error:', err);
    return res.status(500).json({ error: 'Failed to save file' });
  }

  const payload = {
    id: msgId,
    groupId,
    senderId: userId,
    senderName: user.username,
    senderColor: user.icon_color,
    encryptedContent,
    iv,
    type: msgType,
    replyTo: null,
    filename: safeFilename,
    whisperTo: null,
    createdAt,
    editedAt: null,
  };

  io.to(groupId).emit('new_message', payload);
  res.json({ messageId: msgId });
});

// Keep backward-compat alias
app.post('/api/groups/:groupId/upload-image', (req, res) => {
  req.url = `/api/groups/${req.params.groupId}/upload`;
  app.handle(req, res);
});

// DELETE /api/groups/:groupId/members/:userId — kick a member (owner only)
app.delete('/api/groups/:groupId/members/:userId', (req, res) => {
  const { groupId, userId: targetUserId } = req.params;
  const userId = req.session.userId;

  const member = stmts.isMember.get(groupId, userId);
  if (!member) return res.status(403).json({ error: 'Not a member of this group' });

  const group = stmts.findGroupById.get(groupId);
  if (!group || group.created_by !== userId) {
    return res.status(403).json({ error: 'Only the group owner can kick members' });
  }

  if (targetUserId === userId) {
    return res.status(400).json({ error: 'You cannot kick yourself' });
  }

  stmts.deleteMember.run(groupId, targetUserId);
  io.to(groupId).emit('member_kicked', { userId: targetUserId, groupId });
  res.json({ ok: true });
});

// DELETE /api/groups/:groupId — disband group (owner only)
app.delete('/api/groups/:groupId', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;

  const group = stmts.findGroupById.get(groupId);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  if (group.created_by !== userId) {
    return res.status(403).json({ error: 'Only the group owner can disband this group' });
  }

  stmts.deleteGroupMessages.run(groupId);
  stmts.deleteGroupMembers.run(groupId);
  stmts.deleteGroup.run(groupId);

  io.to(groupId).emit('group_disbanded', { groupId });
  res.json({ ok: true });
});

// ── Socket.IO ─────────────────────────────────────────────────────────────────

// Per-socket rate limiting state
const socketRateMap = new Map(); // socketId -> { timestamps: [], lastContent: '', repeatCount: 0 }

// Per-room presence tracking: groupId -> Set<socketId>
const roomPresence = new Map();

function addPresence(groupId, socketId) {
  if (!roomPresence.has(groupId)) roomPresence.set(groupId, new Set());
  roomPresence.get(groupId).add(socketId);
}

function removePresence(groupId, socketId) {
  if (roomPresence.has(groupId)) {
    roomPresence.get(groupId).delete(socketId);
    if (roomPresence.get(groupId).size === 0) roomPresence.delete(groupId);
  }
}

function getPresence(groupId) {
  return roomPresence.has(groupId) ? [...roomPresence.get(groupId)] : [];
}

// Share the express session with Socket.IO
io.use((socket, next) => {
  const fakeRes = {
    getHeader: () => {},
    setHeader: () => {},
    end: () => {},
  };
  sessionMiddleware(socket.request, socket.request.res || fakeRes, next);
});

// Authenticate socket connections
io.use((socket, next) => {
  const userId = socket.request.session && socket.request.session.userId;
  if (!userId) {
    return next(new Error('Not authenticated'));
  }
  socket.userId = userId;
  const user = stmts.findUserById.get(userId);
  if (!user) {
    return next(new Error('User not found'));
  }
  socket.username = user.username;
  socket.iconColor = user.icon_color;
  socket.profilePicture = user.profile_picture;
  next();
});

io.on('connection', (socket) => {
  console.log(`Socket connected: ${socket.username} (${socket.userId})`);
  // Rate limit keyed by userId to prevent multi-connection bypass
  if (!socketRateMap.has(socket.userId)) {
    socketRateMap.set(socket.userId, { timestamps: [], lastContent: '', repeatCount: 0 });
  }

  // ── join_room ──────────────────────────────────────────────────────────────
  socket.on('join_room', (groupId) => {
    if (!groupId) return;

    const member = stmts.isMember.get(groupId, socket.userId);
    if (!member) {
      socket.emit('error', { message: 'Not a member of this group' });
      return;
    }

    // Leave previous rooms (except own socket room)
    for (const room of socket.rooms) {
      if (room !== socket.id) {
        removePresence(room, socket.id);
        socket.leave(room);
      }
    }

    socket.join(groupId);
    socket.currentRoom = groupId;
    addPresence(groupId, socket.id);

    // Notify room of updated presence
    const presenceSockets = getPresence(groupId);
    const onlineUserIds = new Set();
    for (const sid of presenceSockets) {
      const s = io.sockets.sockets.get(sid);
      if (s) onlineUserIds.add(s.userId);
    }
    io.to(groupId).emit('presence_update', { groupId, onlineUserIds: [...onlineUserIds] });

    console.log(`${socket.username} joined room ${groupId}`);
  });

  // ── send_message ──────────────────────────────────────────────────────────
  socket.on('send_message', ({ groupId, encryptedContent, iv, replyTo }) => {
    if (!groupId || !encryptedContent || !iv) return;

    // Server-side rate limiting: max 10 messages per 5 seconds, keyed by userId
    const rateData = socketRateMap.get(socket.userId);
    if (rateData) {
      const now = Date.now();
      rateData.timestamps = rateData.timestamps.filter(t => now - t < 5000);
      if (rateData.timestamps.length >= 10) {
        socket.emit('error', { message: 'Rate limit exceeded. Please slow down.' });
        return;
      }
      // Check for repeated identical messages (3+ in a row)
      if (encryptedContent === rateData.lastContent) {
        rateData.repeatCount = (rateData.repeatCount || 0) + 1;
        if (rateData.repeatCount >= 3) {
          socket.emit('error', { message: 'Don\'t send the same message repeatedly.' });
          return;
        }
      } else {
        rateData.repeatCount = 0;
        rateData.lastContent = encryptedContent;
      }
      rateData.timestamps.push(now);
    }

    // Enforce size cap
    if (encryptedContent.length > MAX_ENCRYPTED_CONTENT_LENGTH) {
      socket.emit('error', { message: 'Message too large.' });
      return;
    }

    const member = stmts.isMember.get(groupId, socket.userId);
    if (!member) {
      socket.emit('error', { message: 'Not a member of this group' });
      return;
    }

    const msgId = uuidv4();
    const createdAt = new Date().toISOString();

    try {
      stmts.insertMessage.run(msgId, groupId, socket.userId, encryptedContent, iv, 'text', replyTo || null, null, null);
    } catch (err) {
      console.error('DB insert message error:', err);
      socket.emit('error', { message: 'Failed to save message' });
      return;
    }

    const payload = {
      id: msgId,
      groupId,
      senderId: socket.userId,
      senderName: socket.username,
      senderColor: socket.iconColor,
      encryptedContent,
      iv,
      type: 'text',
      replyTo: replyTo || null,
      filename: null,
      whisperTo: null,
      createdAt,
      editedAt: null,
    };

    io.to(groupId).emit('new_message', payload);

    // Delivery ack: check if other sockets are in the room
    const roomSockets = getPresence(groupId);
    const hasOtherRecipients = roomSockets.some(sid => sid !== socket.id);
    if (hasOtherRecipients) {
      socket.emit('message_delivered', { messageId: msgId });
    }
  });

  // ── send_whisper ──────────────────────────────────────────────────────────
  socket.on('send_whisper', ({ groupId, encryptedContent, iv, whisperTo, replyTo }) => {
    if (!groupId || !encryptedContent || !iv || !Array.isArray(whisperTo)) return;

    // Rate limiting (same limits as send_message, keyed by userId)
    const rateData = socketRateMap.get(socket.userId);
    if (rateData) {
      const now = Date.now();
      rateData.timestamps = rateData.timestamps.filter(t => now - t < 5000);
      if (rateData.timestamps.length >= 10) {
        socket.emit('error', { message: 'Rate limit exceeded. Please slow down.' });
        return;
      }
      if (encryptedContent === rateData.lastContent) {
        rateData.repeatCount = (rateData.repeatCount || 0) + 1;
        if (rateData.repeatCount >= 3) {
          socket.emit('error', { message: 'Don\'t send the same message repeatedly.' });
          return;
        }
      } else {
        rateData.repeatCount = 0;
        rateData.lastContent = encryptedContent;
      }
      rateData.timestamps.push(now);
    }

    const member = stmts.isMember.get(groupId, socket.userId);
    if (!member) {
      socket.emit('error', { message: 'Not a member of this group' });
      return;
    }

    if (encryptedContent.length > MAX_ENCRYPTED_CONTENT_LENGTH) {
      socket.emit('error', { message: 'Message too large.' });
      return;
    }

    // Validate that every whisper recipient is a member of this group
    for (const recipId of whisperTo) {
      if (!stmts.isMember.get(groupId, String(recipId))) {
        socket.emit('error', { message: 'One or more whisper recipients are not group members.' });
        return;
      }
    }

    const msgId = uuidv4();
    const createdAt = new Date().toISOString();
    // Store whisper recipients as JSON array for safety
    const whisperToStr = JSON.stringify(whisperTo.map(String));

    try {
      stmts.insertMessage.run(msgId, groupId, socket.userId, encryptedContent, iv, 'whisper', replyTo || null, null, whisperToStr);
    } catch (err) {
      console.error('DB insert whisper error:', err);
      socket.emit('error', { message: 'Failed to save whisper' });
      return;
    }

    const payload = {
      id: msgId,
      groupId,
      senderId: socket.userId,
      senderName: socket.username,
      senderColor: socket.iconColor,
      encryptedContent,
      iv,
      type: 'whisper',
      replyTo: replyTo || null,
      filename: null,
      whisperTo: whisperToStr,
      createdAt,
      editedAt: null,
    };

    // Send to sender + recipients only
    const recipientIds = new Set([socket.userId, ...whisperTo.map(String)]);
    const roomSockets = getPresence(groupId);
    for (const sid of roomSockets) {
      const s = io.sockets.sockets.get(sid);
      if (s && recipientIds.has(s.userId)) {
        s.emit('new_message', payload);
      }
    }
  });

  // ── typing ────────────────────────────────────────────────────────────────
  socket.on('typing', ({ groupId }) => {
    if (!groupId) return;
    socket.to(groupId).emit('user_typing', { username: socket.username });
  });

  socket.on('stop_typing', ({ groupId }) => {
    if (!groupId) return;
    socket.to(groupId).emit('user_stop_typing', { username: socket.username });
  });

  // ── disconnect ────────────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    console.log(`Socket disconnected: ${socket.username}`);

    if (socket.currentRoom) {
      removePresence(socket.currentRoom, socket.id);
      const presenceSockets = getPresence(socket.currentRoom);
      const onlineUserIds = new Set();
      for (const sid of presenceSockets) {
        const s = io.sockets.sockets.get(sid);
        if (s) onlineUserIds.add(s.userId);
      }
      io.to(socket.currentRoom).emit('presence_update', {
        groupId: socket.currentRoom,
        onlineUserIds: [...onlineUserIds],
      });
    }

    // Clean up rate-limit state for this user when no more sockets are active.
    // Prune timestamps older than the rate window; if none remain (and no
    // repeated-message flag is set) remove the entry entirely to prevent the
    // map from growing unboundedly (#4 memory leak, #30 stale state).
    const hasOtherSockets = [...io.sockets.sockets.values()].some(
      s => s !== socket && s.userId === socket.userId
    );
    if (!hasOtherSockets) {
      const rateData = socketRateMap.get(socket.userId);
      if (rateData) {
        const now = Date.now();
        rateData.timestamps = rateData.timestamps.filter(t => now - t < 5000);
        if (rateData.timestamps.length === 0) {
          socketRateMap.delete(socket.userId);
        }
      }
    }
  });
});

// ── Start Server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`GayChat server running on port ${PORT}`);
});
