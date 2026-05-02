'use strict';

/**
 * Gchat Desktop — Electron Main Process
 *
 * Responsibilities:
 *  - Create and manage the BrowserWindow
 *  - System tray icon with hide-to-tray behaviour
 *  - Native Windows notifications via IPC
 *  - Taskbar badge (unread count) and frame flash
 *  - Single-instance lock
 *  - Auto-launch on system startup (configurable)
 *  - Auto-updater via electron-updater
 *  - Persistent config via electron-store (server URL, startup preference)
 */

const {
  app,
  BrowserWindow,
  Tray,
  Menu,
  nativeImage,
  ipcMain,
  shell,
  dialog,
  Notification,
} = require('electron');
const path = require('path');
const { autoUpdater } = require('electron-updater');

// ── electron-store is ESM-only in v10+; use dynamic import ────────────────────
let store = null;
async function getStore() {
  if (store) return store;
  const { default: Store } = await import('electron-store');
  store = new Store({
    defaults: {
      serverUrl: 'https://Gchat.up.railway.app',
      launchAtStartup: false,
      windowBounds: { width: 1100, height: 700 },
    },
  });
  return store;
}

// ── State ─────────────────────────────────────────────────────────────────────
let mainWindow = null;
let tray = null;
let isQuitting = false;

// ── Resolve icon path ─────────────────────────────────────────────────────────
// During development the icon lives at build/icon.ico.
// After packaging electron-builder copies it to process.resourcesPath.
function getIconPath() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'icon.ico');
  }
  // Development: look relative to the repo root (two levels up from electron/)
  const devPath = path.join(__dirname, '..', 'build', 'icon.ico');
  const fallback = path.join(__dirname, '..', 'public', 'favicon.svg');
  try {
    require('fs').accessSync(devPath);
    return devPath;
  } catch {
    return fallback;
  }
}

// ── Single-instance lock ──────────────────────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// ── Create window ─────────────────────────────────────────────────────────────
async function createWindow() {
  const cfg = await getStore();
  const { width, height } = cfg.get('windowBounds');
  const serverUrl = cfg.get('serverUrl');

  // Set Windows App User Model ID so notifications group correctly in the
  // Action Center and display the correct app name / icon.
  app.setAppUserModelId('com.Gchat.app');

  const iconPath = getIconPath();
  const icon = nativeImage.createFromPath(iconPath);

  mainWindow = new BrowserWindow({
    width,
    height,
    minWidth: 800,
    minHeight: 500,
    title: 'Gchat ',
    icon,
    backgroundColor: '#1a1a2e',
    show: false, // shown after ready-to-show to avoid flash
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: true,
    },
  });

  // Load the Gchat server
  mainWindow.loadURL(serverUrl).catch(() => {
    mainWindow.loadFile(path.join(__dirname, 'offline.html')).catch(() => {
      mainWindow.webContents.loadURL('data:text/html,<h1>Unable to connect to Gchat server.</h1><p>Check your internet connection and try again.</p>');
    });
  });

  // Show window once content is ready (avoids white flash)
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // Persist window size on resize
  mainWindow.on('resize', async () => {
    const [w, h] = mainWindow.getSize();
    const c = await getStore();
    c.set('windowBounds', { width: w, height: h });
  });

  // Hide to tray instead of closing
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  // Open external links in the default browser, not inside Electron
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Flash taskbar when a new message arrives while window is hidden/unfocused
  mainWindow.on('focus', () => {
    mainWindow.flashFrame(false);
  });
}

// ── System tray ───────────────────────────────────────────────────────────────
async function createTray() {
  const iconPath = getIconPath();
  const trayIcon = nativeImage.createFromPath(iconPath);
  // Resize for tray (16×16 on Windows)
  const trayIconSmall = trayIcon.isEmpty()
    ? trayIcon
    : trayIcon.resize({ width: 16, height: 16 });

  tray = new Tray(trayIconSmall);
  tray.setToolTip('Gchat ');
  updateTrayMenu();

  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.hide();
      } else {
        mainWindow.show();
        mainWindow.focus();
      }
    }
  });

  tray.on('double-click', () => {
    if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
  });
}

function updateTrayMenu(unread = 0) {
  if (!tray) return;
  const label = unread > 0 ? `Gchat (${unread} unread)` : 'Gchat';
  const contextMenu = Menu.buildFromTemplate([
    {
      label,
      enabled: false,
    },
    { type: 'separator' },
    {
      label: 'Open Gchat',
      click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } },
    },
    {
      label: 'Check for Updates',
      click: () => { autoUpdater.checkForUpdatesAndNotify(); },
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => { isQuitting = true; app.quit(); },
    },
  ]);
  tray.setContextMenu(contextMenu);
  tray.setToolTip(unread > 0 ? `Gchat — ${unread} unread message${unread === 1 ? '' : 's'}` : 'Gchat ');
}

// ── IPC handlers (renderer → main) ───────────────────────────────────────────

// Renderer sends unread count whenever it changes
ipcMain.on('set-unread-count', (_event, count) => {
  const n = Math.max(0, Number(count) || 0);
  // Taskbar overlay badge
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setOverlayIcon(
      n > 0 ? createBadgeIcon(n) : null,
      n > 0 ? `${n} unread message${n === 1 ? '' : 's'}` : ''
    );
    // Flash taskbar if window is not focused
    if (n > 0 && !mainWindow.isFocused()) {
      mainWindow.flashFrame(true);
    }
  }
  updateTrayMenu(n);
});

// Renderer requests a native OS notification (for background/unfocused messages)
ipcMain.on('show-notification', (_event, { title, body, groupId }) => {
  if (!Notification.isSupported()) return;
  const notif = new Notification({
    title: title || 'Gchat',
    body: body || 'New message',
    icon: getIconPath(),
    urgency: 'normal',
  });
  notif.on('click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
      // Tell the renderer to switch to the relevant group
      if (groupId) mainWindow.webContents.send('focus-group', groupId);
    }
  });
  notif.show();
});

// Renderer requests launch-at-startup toggle
ipcMain.handle('get-launch-at-startup', async () => {
  const cfg = await getStore();
  return cfg.get('launchAtStartup');
});

ipcMain.handle('set-launch-at-startup', async (_event, enabled) => {
  const cfg = await getStore();
  cfg.set('launchAtStartup', enabled);
  app.setLoginItemSettings({ openAtLogin: !!enabled });
  return enabled;
});

// Renderer requests the current server URL
ipcMain.handle('get-server-url', async () => {
  const cfg = await getStore();
  return cfg.get('serverUrl');
});

// Renderer requests changing the server URL
ipcMain.handle('set-server-url', async (_event, url) => {
  if (!url || typeof url !== 'string') return false;
  const trimmed = url.trim();
  // Basic sanity check — must be http(s)
  if (!/^https?:\/\/.+/.test(trimmed)) return false;
  const cfg = await getStore();
  cfg.set('serverUrl', trimmed);
  if (mainWindow) mainWindow.loadURL(trimmed);
  return true;
});

// ── Badge icon helper ─────────────────────────────────────────────────────────
// Creates a small 20×20 red circle with a number for the taskbar overlay icon.
function createBadgeIcon(count) {
  const label = count > 99 ? '99+' : String(count);
  const size = 20;
  // Build a minimal PNG data-URL via Canvas-like SVG → nativeImage
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}">
    <circle cx="${size / 2}" cy="${size / 2}" r="${size / 2}" fill="#e74c3c"/>
    <text x="50%" y="50%" text-anchor="middle" dominant-baseline="central"
          font-family="Arial,sans-serif" font-size="${label.length > 1 ? 9 : 12}"
          font-weight="bold" fill="white">${label}</text>
  </svg>`;
  return nativeImage.createFromDataURL(
    'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64')
  );
}

// ── Auto-updater ──────────────────────────────────────────────────────────────
function setupAutoUpdater() {
  autoUpdater.autoDownload = false;

  autoUpdater.on('update-available', (info) => {
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'Update Available',
      message: `Gchat ${info.version} is available.`,
      detail: 'Would you like to download and install it?',
      buttons: ['Download', 'Later'],
      defaultId: 0,
    }).then(({ response }) => {
      if (response === 0) autoUpdater.downloadUpdate();
    });
  });

  autoUpdater.on('update-downloaded', () => {
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'Update Ready',
      message: 'The update has been downloaded.',
      detail: 'Restart Gchat to apply the update.',
      buttons: ['Restart Now', 'Later'],
      defaultId: 0,
    }).then(({ response }) => {
      if (response === 0) { isQuitting = true; autoUpdater.quitAndInstall(); }
    });
  });

  autoUpdater.on('error', (err) => {
    console.error('[updater] error:', err.message);
  });

  // Only check in packaged builds where GitHub release config is valid
  if (app.isPackaged) {
    autoUpdater.checkForUpdatesAndNotify().catch(() => {});
  }
}

// ── App lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  // Apply stored startup preference
  const cfg = await getStore();
  app.setLoginItemSettings({ openAtLogin: cfg.get('launchAtStartup') });

  await createWindow();
  await createTray();
  setupAutoUpdater();
});

app.on('window-all-closed', () => {
  // On macOS keep the app running in the tray even with no windows.
  // On Windows / Linux quit if all windows are closed and not going to tray.
  if (process.platform !== 'darwin' && isQuitting) {
    app.quit();
  }
});

app.on('activate', () => {
  // macOS: re-create window when dock icon is clicked
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  } else if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
});
