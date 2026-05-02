# Gchat 

A modern, **end-to-end encrypted** group chat application built with Node.js, Express, Socket.IO, and SQLite — deployable in one click to [Railway.app](https://railway.app).

---

## Features

- 🔐 **AES-256-GCM client-side encryption** — plaintext never leaves your browser unencrypted
- 🔑 **Per-group saved keys** — set a key once per group; messages auto-encrypt/decrypt
- 👤 **Account registration** with custom username, icon color, and profile picture
- 🖼️ **Custom profile pictures** — upload profile pictures (up to 2MB) or use color + initial
- 💬 **Group chats** — create or join groups via shareable codes
- 📎 **Image & file sharing** — 25GB limit, auto-compressed images, automatic file download
- 🔍 **Image viewer** — click images to magnify in full-screen modal
- ↩ **Quote/Reply** — reply to any message with a preview quote
- ✏️ **Message editing** — edit your own text/whisper messages; edited messages show an "(edited)" badge
- 🤫 **Whisper mode** — send private messages to selected members only
- 👑 **Group owner controls** — kick members, disband group, clear history, rename group, allow member clear
- 🔍 **Search messages** — client-side search with highlight
- 📥 **Export chat** — download full chat history as TXT
- 😊 **Emoji picker** — grid of 80 emojis
- 🌑 **Modern dark UI** — glassmorphism, gradient bubbles, smooth animations
- 📱 **Mobile responsive** — collapsible sidebars, optimized for small screens
- 🔔 **Page title notifications** — get alerted to new messages when tab is not focused
- 🔔 **Native OS notifications** — Windows/macOS/Linux system notifications with click-to-focus (desktop app)
- 🖥️ **Windows desktop app** — Electron wrapper with system tray, taskbar badge, auto-launch, and auto-update
- ⚡ **Real-time** via Socket.IO — typing indicators, presence, delivery receipts
- 🛡 **Anti-spam** — client + server rate limiting, brute-force login protection

---

## How Encryption Works

1. **Set a group key** — click "🔑 Set Key" in the right panel and enter any passphrase.
2. The key is stored in `sessionStorage` (lost when you close the tab) and never sent to the server.
3. The app derives an AES-256 key using **PBKDF2** (100,000 iterations, SHA-256) with your passphrase + the group's UUID as salt.
4. Every message is encrypted with **AES-256-GCM** entirely in your browser before being sent.
5. Only the **ciphertext (base64) + IV (base64)** are stored in SQLite on the server.
6. Recipients who have set the same key see messages automatically decrypted.
7. If someone doesn't have the key, messages appear as `[No key — set group key to decrypt]`.

> **The server never sees plaintext. Encryption keys are never stored or transmitted.**

---

## ⚠️ Persistent Storage on Railway (IMPORTANT)

By default, Railway's filesystem is **ephemeral** — it is wiped on every redeploy, which means your SQLite database (users, groups, messages) will be lost.

### To persist data across deploys:

1. In your Railway project, go to **New** → **Volume**.
2. Mount the volume at **`/data`**.
3. In the **Variables** tab, add: `DB_PATH` = `/data/Gchat.db`

Railway will now store the database file on the mounted volume and it will survive redeploys.

> **Without this step, all users, groups, and messages are deleted every time you deploy.**

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js, Express.js |
| Real-time | Socket.IO |
| Database | SQLite via `better-sqlite3` |
| Auth | bcrypt, express-session + connect-sqlite3 |
| Encryption | AES-256-GCM via Web Crypto API (client-side only) |
| Frontend | Vanilla HTML, CSS, JavaScript |
| Desktop | Electron (Windows / macOS / Linux) |
| Deployment | Railway.app |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | ✅ Yes | Secret for signing session cookies. Use a long random string in production. |
| `PORT` | Set by Railway | Port the server listens on. Defaults to `3000` locally. |
| `DB_PATH` | No | Full path for the SQLite database file (e.g. `/data/Gchat.db`). Useful with Railway Volumes for persistence. Defaults to `./Gchat.db`. |
| `ADMIN_SECRET` | No | Set this to enable the `GET /api/admin/users` endpoint. Requests must supply `Authorization: Bearer <value>`. |

---

## Admin: Viewing Registered Users

1. In your Railway project's **Variables** tab, set `ADMIN_SECRET` to a strong secret string.
2. Call the endpoint with your secret:

   ```bash
   curl https://<your-railway-url>/api/admin/users \
     -H "Authorization: Bearer YOUR_SECRET"
   ```

3. The response is a JSON array of user objects:

   ```json
   [
     {
       "id": "uuid",
       "username": "alice",
       "iconColor": "#4A90D9",
       "createdAt": "2024-01-01T00:00:00.000Z"
     }
   ]
   ```

> **Note:** Passwords are bcrypt-hashed and **CANNOT be recovered** — by design. The admin endpoint intentionally omits password hashes.

---

## Persistent Storage on Railway

See the **⚠️ Persistent Storage on Railway** section above — it is critical to set this up before going live.

---

## Deploy to Railway

1. **Fork** this repository to your GitHub account.
2. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**.
3. Select your fork of `Gchat`.
4. Railway will auto-detect Node.js and run `npm start`.
5. In the **Variables** tab, add: `SESSION_SECRET` = `<some long random string>`.
6. Your app will be live at the auto-generated Railway URL!

---

## Windows Desktop App (Electron)

Gchat can be run as a native Windows desktop app (also supports macOS and Linux) using Electron. The desktop app adds:

- 🖥️ **System tray** — minimises to tray; click to show/hide
- 🔔 **Native notifications** — Windows Action Center alerts with click-to-focus on the right group
- 🔢 **Taskbar badge** — red unread-count overlay on the taskbar icon
- ⚡ **Taskbar flash** — taskbar button flashes on new messages when window is in background
- 🚀 **Auto-launch** — optionally start with Windows
- 🔄 **Auto-update** — receives updates via GitHub Releases

### Quick start (development)

```bash
# Install all dependencies (including devDependencies for Electron)
npm install

# Start the server
node server.js &

# Launch the desktop app
npm run electron
```

### Build a Windows installer

```bash
npm run build:win
# Output: dist/Gchat Setup <version>.exe  (installer)
#         dist/Gchat <version>.exe         (portable)
```

See **[INSTALL_DESKTOP.md](INSTALL_DESKTOP.md)** for the full installation guide, including icon setup, server URL configuration, notification permissions, and troubleshooting.

> **Railway note**: The `railway.json` build command is set to `npm install --omit=dev`, so `electron` and `electron-builder` are never installed on the Railway server — they are `devDependencies` only and do not affect the web deployment.

---

## Local Development

```bash
# Install dependencies
npm install

# Start the server (runs on http://localhost:3000)
node server.js
```

Open `http://localhost:3000` in your browser.

---

## File Structure

```
/
├── server.js          # Express + Socket.IO backend
├── package.json       # Dependencies and npm start script
├── railway.json       # Railway deployment config
├── INSTALL_DESKTOP.md # Desktop app installation guide
├── .gitignore
├── README.md
├── electron/
│   ├── main.js        # Electron main process (window, tray, IPC, updater)
│   └── preload.js     # Secure renderer ↔ main bridge (contextBridge)
├── build/             # Icon assets for electron-builder (not committed; add icon.ico here)
└── public/
    ├── index.html     # Sign In / Sign Up page
    ├── chat.html      # Main chat interface (WeChat-style)
    ├── style.css      # Complete stylesheet
    └── app.js         # Frontend: crypto, socket, UI logic
```

---

## Security Notes

- Sessions are stored in a local SQLite file (`sessions.db`) and signed with `SESSION_SECRET`.
- Passwords are hashed with **bcrypt** (cost factor 12).
- The `*.db` files are git-ignored and should never be committed.
- In production (Railway), session cookies are set with `httpOnly: true` and `secure: true`.
