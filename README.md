# GayChat 🏳️‍🌈

A WeChat-style, text-only, **end-to-end encrypted** group chat application built with Node.js, Express, Socket.IO, and SQLite — deployable in one click to [Railway.app](https://railway.app).

---

## Features

- 🔐 **AES-256-GCM client-side encryption** — plaintext never leaves your browser unencrypted
- 👤 **Account registration** with custom username and icon color
- 💬 **Group chats** — create or join groups via shareable codes
- 🔑 **Manual key entry** — type an encryption key before sending; share the key with recipients out-of-band
- 🔓 **Per-message decryption** — click the 🔓 button on any message and enter the key to read it
- ⚡ **Real-time messaging** via Socket.IO with typing indicators
- 🎨 **WeChat-inspired UI** — three-panel layout, green chat bubbles, dark sidebar
- 📱 **Mobile responsive** — collapsible sidebar, optimized for small screens

---

## How Encryption Works

1. **You type a message** and click Send.
2. A modal prompts you for an **encryption key** (any passphrase you choose).
3. The app derives an AES-256 key using **PBKDF2** (100 000 iterations, SHA-256) with your passphrase + the group's UUID as salt.
4. The message is encrypted with **AES-256-GCM** entirely in your browser.
5. Only the **ciphertext (base64) + IV (base64)** are sent to the server and stored in SQLite.
6. To **read** a message, recipients click 🔓 and enter the same key — decryption also happens in the browser.

> **The server never sees plaintext. Encryption keys are never stored or transmitted.**

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js, Express.js |
| Real-time | Socket.IO |
| Database | SQLite via `better-sqlite3` |
| Auth | bcrypt, express-session + connect-sqlite3 |
| Encryption | AES-256-GCM via Web Crypto API (client-side only) |
| Frontend | Vanilla HTML, CSS, JavaScript |
| Deployment | Railway.app |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | ✅ Yes | Secret for signing session cookies. Use a long random string in production. |
| `PORT` | Set by Railway | Port the server listens on. Defaults to `3000` locally. |

---

## Deploy to Railway

1. **Fork** this repository to your GitHub account.
2. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**.
3. Select your fork of `GayChat`.
4. Railway will auto-detect Node.js and run `npm start`.
5. In the **Variables** tab, add: `SESSION_SECRET` = `<some long random string>`.
6. Your app will be live at the auto-generated Railway URL!

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
├── .gitignore
├── README.md
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
