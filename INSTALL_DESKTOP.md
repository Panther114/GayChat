# Gchat Desktop — Windows Setup Guide

Gchat Desktop is a Windows wrapper for the hosted Gchat web app. It keeps the same chat experience and adds desktop features like tray support, native notifications, startup launch, and automatic updates.

---

## What the desktop app does

- Uses the same hosted Gchat service after setup
- Opens a short **first-run setup wizard**
- Always connects to **`https://gchat.up.railway.app`**
- Requires an **internet connection**
- Can **launch with Windows**
- **Downloads updates automatically** and asks before restart

---

## Option A — Install the packaged Windows build

If a release is available:

1. Open the repository **[Releases](../../releases)** page.
2. Download **`Gchat Setup <version>.exe`**.
3. Double-click the installer.
4. Complete the built-in setup steps on first launch.
5. Gchat opens the hosted sign-in page.

> **Windows SmartScreen warning**: If Windows shows “Windows protected your PC”, click **More info → Run anyway**. This happens because the executable is not code-signed yet.

---

## Option B — Build it yourself

### 1. Clone the repository

```bash
git clone https://github.com/Panther114/Gchat.git
cd Gchat
```

### 2. Install dependencies

```bash
# Use Node 20 for Windows desktop packaging
npm install --include=dev
```

### 3. Launch the desktop app

```bash
npm run electron
```

The desktop app will show the setup wizard and then open the hosted Railway deployment.

### 4. Build the Windows package

```bash
npm run build:win
```

This creates Windows output in `dist/`:

| File | Description |
|---|---|
| `Gchat Setup <version>.exe` | Windows installer |
| `Gchat <version>.exe` | Portable build |

---

## First-run setup

The first time Gchat Desktop launches, it walks through:

1. **Welcome** — quick overview of the desktop app.
2. **Connection check** — confirms that `https://gchat.up.railway.app` is reachable.
3. **Notifications** — optionally enables native Windows alerts.
4. **Startup preference** — chooses whether Gchat opens with Windows.
5. **Finish** — saves settings and opens sign in.

The wizard only has to be completed once per Windows user profile.

---

## Server behavior

This desktop build is intentionally **not configurable** for self-hosting.

- The app always targets: `https://gchat.up.railway.app`
- The URL is locked so setup stays simple
- There is **no offline mode** in the desktop shell
- If the hosted app is unreachable, Gchat shows a retry screen until the connection returns

---

## Launch at startup

The setup wizard includes a **Launch Gchat at startup** choice.

- If enabled, Gchat starts with Windows and restores the desktop shell.
- If disabled, users can still launch it manually whenever they want.

The chosen value is saved in the local Electron config under `%APPDATA%\Gchat\config.json`.

---

## Notifications

If notifications are allowed:

- new messages can trigger **native Windows notifications**
- clicking a notification brings Gchat to the front
- the taskbar overlay badge and tray state stay aligned with unread activity

If notifications are denied, the app still works, but native desktop alerts stay disabled until Windows permission settings are changed.

---

## System tray behavior

- Closing the main window hides Gchat to the **system tray** instead of exiting.
- Clicking the tray icon shows or hides the app.
- Right-clicking the tray icon opens the tray menu: **Open**, **Check for Updates**, **Quit**.

---

## Updating

When a newer GitHub Release is available:

1. Gchat detects it automatically.
2. The update downloads in the background.
3. When the download is ready, Gchat prompts the user to restart and install it.

---

## Troubleshooting

| Problem | What to do |
|---|---|
| `'electron-builder' is not recognized as an internal or external command` | Run `npm install --include=dev` in the repo root, then retry `npm run build:win`. This error means the Electron build tools were not installed. |
| The setup wizard will not continue past the connection step | Confirm the internet connection is working and `https://gchat.up.railway.app` is reachable. |
| Gchat opens a recovery screen instead of the sign-in page | The hosted Railway app could not be reached. Use the retry button after the connection improves. |
| Notifications do not appear | Check Windows notification settings and confirm the permission was allowed during setup. |
| A second app window appears | Gchat uses a single-instance lock. If this still happens, remove `%APPDATA%\Gchat\` and relaunch. |

---

## File locations (Windows)

| Purpose | Path |
|---|---|
| Desktop config (wizard completion, startup choice) | `%APPDATA%\Gchat\config.json` |
| Electron user data | `%APPDATA%\Gchat\` |

---

## Security notes

- The desktop app keeps `contextIsolation: true`, `nodeIntegration: false`, and `sandbox: true`.
- External links still open in the default browser instead of inside Electron.
- The local wizard stores only desktop shell preferences; chat authentication still happens on the hosted app after setup.
- Group encryption keys remain client-side and are not handled by the desktop wrapper.
