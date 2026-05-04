# Gchat Desktop — Windows Installation Guide

Gchat Desktop is a Windows-focused Electron wrapper for the hosted Gchat web app. It keeps the same chat UI after setup, then adds desktop-native features such as system tray support, launch-at-startup, native notifications, unread badge overlays, and automatic GitHub-based updates.

---

## What the desktop app now does

- Runs as a **Windows desktop app** with the same interface as the web version after setup
- Opens a **first-run setup wizard** instead of asking users to run console commands
- Stays **locked to the official Railway deployment**: `https://gchat.up.railway.app`
- Requires an **online connection** at startup and during use
- Can **optionally launch when Windows boots**
- **Downloads updates automatically** from GitHub Releases and asks before restarting to install

---

## Option A — Download a packaged Windows build

If a maintainer has published a release:

1. Open the repository **[Releases](../../releases)** page.
2. Download either:
   - `Gchat Setup <version>.exe` for the normal Windows installer, or
   - `Gchat <version>.exe` for the portable build.
3. Run the file.
4. On first launch, complete the built-in setup wizard.
5. After setup finishes, the app opens the hosted Gchat sign-in page.

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
npm install --include=dev
```

### 3. Launch the desktop app in development

```bash
npm run electron
```

The desktop shell will show the first-run setup wizard, then connect to the hosted Railway deployment.

### 4. Build the Windows packages

```bash
npm run build:win
```

This outputs Windows packages in `dist/`:

| File | Description |
|---|---|
| `Gchat Setup <version>.exe` | Windows installer |
| `Gchat <version>.exe` | Portable build |

---

## First-run setup wizard

The first time Gchat Desktop launches, it walks the user through a guided setup flow:

1. **Welcome + privacy summary** — explains encryption, hosted usage, and desktop behavior.
2. **Connection check** — verifies that `https://gchat.up.railway.app` is reachable.
3. **Notification permission** — prompts for native Windows alerts.
4. **Startup preference** — lets the user choose whether Gchat launches when Windows boots.
5. **Finish** — saves the desktop settings and opens the hosted sign-in page.

The wizard only has to be completed once per Windows user profile.

---

## Server behavior

This desktop build is intentionally **not configurable** for self-hosting.

- The app always targets: `https://gchat.up.railway.app`
- The URL is locked so support and setup stay simple
- There is **no offline mode** in the desktop shell
- If the hosted app is unreachable, Gchat shows a retry screen until the connection returns

---

## Auto-launch at startup

The first-run wizard includes a **Launch Gchat at startup** choice.

- If enabled, Gchat starts with Windows and restores the desktop shell.
- If disabled, users can still launch it manually whenever they want.

The chosen value is saved in the local Electron config under `%APPDATA%\Gchat\config.json`.

---

## Notifications

If notifications are allowed during setup:

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
