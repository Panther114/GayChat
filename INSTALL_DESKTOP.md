# Gchat Desktop — Installation Guide

Gchat Desktop is an Electron-based Windows (and cross-platform) desktop application that wraps the Gchat web app and adds native OS features: system tray, Windows Action Center notifications, taskbar badge, flash-on-message, and auto-launch at startup.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Node.js | ≥ 18.0.0 |
| npm | ≥ 9.0.0 |
| Git | any recent version |
| A running Gchat server | (Railway deployment or local `node server.js`) |

---

## Option A — Download a Pre-Built Installer (Recommended)

If a maintainer has published a release:

1. Go to the **[Releases](../../releases)** page of this repository.
2. Download the latest `Gchat-Setup-<version>.exe` (installer) or `Gchat-<version>-portable.exe` (no install needed).
3. Run the installer / portable executable.
4. On first launch, Gchat Desktop will connect to the configured server URL.

> **Windows SmartScreen warning**: If you see a "Windows protected your PC" warning, click **More info → Run anyway**. This appears because the executable is not yet signed with a commercial code-signing certificate.

---

## Option B — Build from Source

### 1. Clone the repository

```bash
git clone https://github.com/Panther114/Gchat.git
cd Gchat
```

### 2. Install all dependencies (including devDependencies)

```bash
npm install
```

> **Note**: This installs `electron` and `electron-builder` which are listed as `devDependencies`. These are intentionally excluded from Railway server deployments via the `npm install --omit=dev` build command in `railway.json`.

### 3. Run in development mode (no packaging)

```bash
# Point the app at your local dev server (start the server first)
node server.js &

# Launch the desktop app
npm run electron
```

The app will open a native window loading `http://localhost:3000` by default. You can change the server URL from the app's settings (see [Changing the Server URL](#changing-the-server-url)).

### 4. Build a Windows installer

```bash
npm run build:win
```

This produces the following files in the `dist/` folder:

| File | Description |
|---|---|
| `Gchat Setup <version>.exe` | NSIS installer — installs to Program Files |
| `Gchat <version>.exe` | Portable executable — no installation needed |

> **Icon**: Before building for distribution, place a multi-resolution Windows icon at `build/icon.ico` (recommended sizes: 16×16, 32×32, 48×48, 256×256). You can convert `public/favicon.svg` to `.ico` using tools like [CloudConvert](https://cloudconvert.com/svg-to-ico) or ImageMagick:
>
> ```bash
> convert -background transparent public/favicon.svg -define icon:auto-resize=256,48,32,16 build/icon.ico
> ```

### 5. Build for macOS / Linux (optional)

```bash
npm run build:mac    # Produces a .dmg for macOS
npm run build:linux  # Produces .AppImage and .deb for Linux
```

---

## Changing the Server URL

By default the desktop app connects to the server URL stored in its local config (defaults to `https://Gchat.up.railway.app`). To point it at a different server:

**Via the browser console (developer tools):**

1. Open DevTools: **Ctrl + Shift + I** (or **F12**).
2. In the **Console** tab, run:

```js
await window.electronAPI.setServerUrl('https://your-server-url.example.com');
```

The window will reload and connect to the new URL. The setting is persisted across restarts.

---

## Auto-Launch at Startup

To make Gchat Desktop start automatically when Windows starts:

1. Open DevTools (**Ctrl + Shift + I**) and run in the Console:

```js
await window.electronAPI.setLaunchAtStartup(true);
// Returns: true
```

To disable:

```js
await window.electronAPI.setLaunchAtStartup(false);
```

---

## System Tray

- Gchat Desktop minimises to the **system tray** (bottom-right corner of the taskbar) when you click the ✕ close button. The app keeps running in the background.
- **Click** the tray icon to show/hide the main window.
- **Right-click** the tray icon for the context menu: Open, Check for Updates, Quit.
- When there are unread messages, the tray tooltip shows the unread count.

---

## Notifications

- Gchat Desktop sends **native Windows notifications** (visible in the Action Center) when a new message arrives while the window is hidden or not in focus.
- Clicking a notification brings the window to the front and navigates to the relevant group.
- The **taskbar icon** shows a red badge overlay with the unread count.
- The taskbar button **flashes** when a new message arrives while the window is in the background.

### Granting notification permission (first run)

On first launch, the browser engine inside Electron will prompt for notification permission. Click **Allow** to enable native notifications.

---

## Updating

When a new version is available (requires GitHub Releases to be configured):

1. A dialog will appear: **"Gchat X.Y.Z is available."**
2. Click **Download** to download the update in the background.
3. When the download completes, click **Restart Now** to apply it.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Blank white screen on launch | Check that the server URL is correct and the server is running. |
| Notifications not appearing | Open DevTools console and check for `Notification.permission`. Run `Notification.requestPermission()` manually if it shows `"denied"`. On Windows 11, also check **Settings → System → Notifications** and ensure Gchat is allowed. |
| `npm run build:win` fails with "icon not found" | Create `build/icon.ico` as described in the [Build section](#4-build-a-windows-installer). |
| `ELECTRON_SKIP_BINARY_DOWNLOAD` warning in CI | This is expected on Railway where Electron is not installed. The `npm install --omit=dev` command in `railway.json` prevents Electron from being downloaded on the server. |
| App opens a second window on launch | The single-instance lock should prevent this. If it persists, delete `%APPDATA%\Gchat\` and relaunch. |

---

## File Locations (Windows)

| Purpose | Path |
|---|---|
| App config (server URL, startup pref) | `%APPDATA%\Gchat\config.json` |
| App logs | `%APPDATA%\Gchat\logs\` |
| Electron user data | `%APPDATA%\Gchat\` |

---

## Security Notes

- The desktop app uses `contextIsolation: true`, `nodeIntegration: false`, and `sandbox: true` — the web content cannot access Node.js APIs directly.
- External links (e.g., URLs in messages) are opened in your default browser, not inside Electron.
- The preload script (`electron/preload.js`) exposes only a narrow `window.electronAPI` surface via `contextBridge`.
- For production distribution, sign the executable with a code-signing certificate to avoid Windows SmartScreen warnings.
