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

// ── App & Server ──────────────────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database('gaychat.db');

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

// ── Prepared Statements ───────────────────────────────────────────────────────
const stmts = {
  // Users
  findUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  findUserById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare(
    'INSERT INTO users (id, username, password_hash, icon_color) VALUES (?, ?, ?, ?)'
  ),

  // Groups
  insertGroup: db.prepare(
    'INSERT INTO group_chats (id, name, code, created_by) VALUES (?, ?, ?, ?)'
  ),
  findGroupByCode: db.prepare('SELECT * FROM group_chats WHERE code = ?'),
  findGroupById: db.prepare('SELECT * FROM group_chats WHERE id = ?'),

  // Members
  insertMember: db.prepare(
    'INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)'
  ),
  isMember: db.prepare(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?'
  ),
  getUserGroups: db.prepare(`
    SELECT g.id, g.name, g.code, g.created_by, g.created_at
    FROM group_chats g
    JOIN group_members gm ON g.id = gm.group_id
    WHERE gm.user_id = ?
    ORDER BY g.created_at DESC
  `),
  getGroupMembers: db.prepare(`
    SELECT u.id, u.username, u.icon_color
    FROM users u
    JOIN group_members gm ON u.id = gm.user_id
    WHERE gm.group_id = ?
    ORDER BY gm.joined_at ASC
  `),

  // Messages
  insertMessage: db.prepare(
    'INSERT INTO messages (id, group_id, sender_id, encrypted_content, iv) VALUES (?, ?, ?, ?, ?)'
  ),
  getMessages: db.prepare(`
    SELECT m.id, m.group_id, m.sender_id, u.username AS sender_name,
           u.icon_color AS sender_color, m.encrypted_content, m.iv, m.created_at
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE m.group_id = ?
    ORDER BY m.created_at ASC
    LIMIT 100
  `),
  getLastMessages: db.prepare(`
    SELECT m.id, m.group_id, m.sender_id, u.username AS sender_name,
           u.icon_color AS sender_color, m.encrypted_content, m.iv, m.created_at
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE m.group_id = ?
    ORDER BY m.created_at DESC
    LIMIT 100
  `),
};

// ── Session Middleware ────────────────────────────────────────────────────────
const sessionMiddleware = session({
  store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
  secret: process.env.SESSION_SECRET || 'gaychat-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // SameSite=strict prevents cross-origin cookie sending (primary CSRF defence)
    sameSite: 'strict',
    // Allow secure cookies only in production (Railway uses HTTPS)
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  },
});

// ── Express Middleware ────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(sessionMiddleware);

// ── CSRF Protection ───────────────────────────────────────────────────────────
// Double-submit token pattern: token stored in session, sent as custom header.
// Browsers cannot set custom headers in cross-origin requests without CORS preflight,
// so this provides defence-in-depth alongside SameSite=strict cookies.

function getCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

// CSRF exempt paths (GET requests and the CSRF token endpoint itself are safe)
const CSRF_EXEMPT = [
  '/auth/csrf',
  '/auth/register',
  '/auth/login',
  '/auth/me',
];

function csrfProtect(req, res, next) {
  // Skip safe HTTP methods and exempt paths
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (CSRF_EXEMPT.includes(req.path)) return next();

  const token = req.headers['x-csrf-token'];
  const sessionToken = req.session && req.session.csrfToken;

  // timingSafeEqual requires equal-length buffers; reject if lengths differ
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
// When mounted with app.use('/api', ...), req.path is relative to /api
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

// ── Helper: format user object ────────────────────────────────────────────────
function formatUser(user) {
  return { id: user.id, username: user.username, iconColor: user.icon_color };
}

// ── Auth Routes ───────────────────────────────────────────────────────────────

// GET /api/auth/csrf — return a CSRF token for this session (creates one if absent)
app.get('/api/auth/csrf', (req, res) => {
  const token = getCsrfToken(req);
  req.session.save(() => res.json({ csrfToken: token }));
});

// GET /api/auth/me — return current session user
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

// POST /api/auth/register — create account and log in
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

  // Check duplicate username
  const existing = stmts.findUserByUsername.get(username);
  if (existing) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const id = uuidv4();
    const color = iconColor || '#4A90D9';

    stmts.insertUser.run(id, username, passwordHash, color);

    // Auto-login
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

// POST /api/auth/login — authenticate and log in
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = stmts.findUserByUsername.get(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  try {
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    req.session.userId = user.id;
    req.session.save(() => {
      res.json(formatUser(user));
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout — destroy session
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// ── Group Routes ──────────────────────────────────────────────────────────────

// POST /api/groups/create — create a new group and auto-join creator
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

  // Check duplicate code
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
  });
});

// POST /api/groups/join — join a group by its code
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

  res.json({
    id: group.id,
    name: group.name,
    code: group.code,
    createdBy: group.created_by,
  });
});

// GET /api/groups/mine — list all groups the user belongs to
app.get('/api/groups/mine', (req, res) => {
  const userId = req.session.userId;
  const groups = stmts.getUserGroups.all(userId);
  res.json(
    groups.map((g) => ({
      id: g.id,
      name: g.name,
      code: g.code,
      createdBy: g.created_by,
    }))
  );
});

// GET /api/groups/:groupId/messages — last 100 messages (ASC order)
app.get('/api/groups/:groupId/messages', (req, res) => {
  const { groupId } = req.params;
  const userId = req.session.userId;

  // Verify membership
  const member = stmts.isMember.get(groupId, userId);
  if (!member) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }

  // Fetch last 100 in DESC, then reverse to ASC
  const rows = stmts.getLastMessages.all(groupId).reverse();
  res.json(
    rows.map((m) => ({
      id: m.id,
      groupId: m.group_id,
      senderId: m.sender_id,
      senderName: m.sender_name,
      senderColor: m.sender_color,
      encryptedContent: m.encrypted_content,
      iv: m.iv,
      createdAt: m.created_at,
    }))
  );
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
    }))
  );
});

// ── Socket.IO ─────────────────────────────────────────────────────────────────

// Share the express session with Socket.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

// Authenticate socket connections
io.use((socket, next) => {
  const userId = socket.request.session && socket.request.session.userId;
  if (!userId) {
    return next(new Error('Not authenticated'));
  }
  // Attach user info to socket for convenience
  socket.userId = userId;
  const user = stmts.findUserById.get(userId);
  if (!user) {
    return next(new Error('User not found'));
  }
  socket.username = user.username;
  socket.iconColor = user.icon_color;
  next();
});

io.on('connection', (socket) => {
  console.log(`Socket connected: ${socket.username} (${socket.userId})`);

  // ── join_room: verify membership then join Socket.IO room ──────────────────
  socket.on('join_room', (groupId) => {
    if (!groupId) return;

    const member = stmts.isMember.get(groupId, socket.userId);
    if (!member) {
      socket.emit('error', { message: 'Not a member of this group' });
      return;
    }

    // Leave all previous rooms except the socket's own room
    for (const room of socket.rooms) {
      if (room !== socket.id) {
        socket.leave(room);
      }
    }

    socket.join(groupId);
    console.log(`${socket.username} joined room ${groupId}`);
  });

  // ── send_message: save to DB then broadcast to room ───────────────────────
  socket.on('send_message', ({ groupId, encryptedContent, iv }) => {
    if (!groupId || !encryptedContent || !iv) return;

    // Verify membership
    const member = stmts.isMember.get(groupId, socket.userId);
    if (!member) {
      socket.emit('error', { message: 'Not a member of this group' });
      return;
    }

    const msgId = uuidv4();
    const createdAt = new Date().toISOString();

    try {
      stmts.insertMessage.run(msgId, groupId, socket.userId, encryptedContent, iv);
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
      createdAt,
    };

    // Broadcast to all sockets in the room (including sender)
    io.to(groupId).emit('new_message', payload);
  });

  // ── typing: broadcast to others in the room ───────────────────────────────
  socket.on('typing', ({ groupId }) => {
    if (!groupId) return;
    socket.to(groupId).emit('user_typing', { username: socket.username });
  });

  // ── stop_typing: broadcast to others ─────────────────────────────────────
  socket.on('stop_typing', ({ groupId }) => {
    if (!groupId) return;
    socket.to(groupId).emit('user_stop_typing', { username: socket.username });
  });

  socket.on('disconnect', () => {
    console.log(`Socket disconnected: ${socket.username}`);
  });
});

// ── Start Server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`GayChat server running on port ${PORT}`);
});
