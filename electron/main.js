'use strict';

/**
 * Gchat Desktop — Electron Main Process
 *
 * Responsibilities:
 *  - Create and manage the BrowserWindow
 *  - First-run onboarding wizard and startup recovery pages
 *  - System tray icon with hide-to-tray behaviour
 *  - Native Windows notifications via IPC
 *  - Taskbar badge (unread count) and frame flash
 *  - Single-instance lock
 *  - Auto-launch on system startup (configurable)
 *  - Auto-updater via electron-updater
 *  - Persistent config via electron-store
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
const fs = require('fs');
const path = require('path');
const { autoUpdater } = require('electron-updater');

const OFFICIAL_SERVER_URL = 'https://gchat.up.railway.app';
const APP_USER_MODEL_ID = 'com.Gchat.app';

// ── electron-store is ESM-only in v10+; use dynamic import ────────────────────
let store = null;
async function getStore() {
  if (store) return store;
  const { default: Store } = await import('electron-store');
  store = new Store({
    defaults: {
      serverUrl: OFFICIAL_SERVER_URL,
      launchAtStartup: false,
      windowBounds: { width: 1100, height: 700 },
      onboardingCompleted: false,
    },
  });
  return store;
}

// ── State ─────────────────────────────────────────────────────────────────────
let mainWindow = null;
let tray = null;
let isQuitting = false;
let lastLoadError = null;

// ── Resolve icon path ─────────────────────────────────────────────────────────
function getIconPath() {
  const candidates = [
    path.join(__dirname, '..', 'public', 'favicon.svg'),
    path.join(__dirname, '..', 'build', 'icon.ico'),
    path.join(process.resourcesPath, 'icon.ico'),
  ];

  for (const candidate of candidates) {
    if (!candidate) continue;
    try {
      fs.accessSync(candidate);
      return candidate;
    } catch {
      // try next candidate
    }
  }

  return '';
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

function isHostedUrl(url) {
  return typeof url === 'string' && url.startsWith(OFFICIAL_SERVER_URL);
}

async function showOnboardingWizard() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  await mainWindow.loadFile(path.join(__dirname, 'wizard.html'));
}

async function showOfflineScreen() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  await mainWindow.loadFile(path.join(__dirname, 'offline.html'));
}

async function loadHostedApp() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try {
    await mainWindow.loadURL(OFFICIAL_SERVER_URL);
  } catch (error) {
    lastLoadError = {
      errorCode: 'LOAD_FAILED',
      errorDescription: error?.message || 'Unable to connect to the hosted app.',
      url: OFFICIAL_SERVER_URL,
      failedAt: new Date().toISOString(),
    };
    await showOfflineScreen();
  }
}

async function routeInitialView() {
  const cfg = await getStore();
  cfg.set('serverUrl', OFFICIAL_SERVER_URL);
  if (!cfg.get('onboardingCompleted')) {
    await showOnboardingWizard();
    return;
  }
  await loadHostedApp();
}

// ── Create window ─────────────────────────────────────────────────────────────
async function createWindow() {
  const cfg = await getStore();
  const { width, height } = cfg.get('windowBounds');

  app.setAppUserModelId(APP_USER_MODEL_ID);

  const iconPath = getIconPath();
  const icon = nativeImage.createFromPath(iconPath);

  mainWindow = new BrowserWindow({
    width,
    height,
    minWidth: 880,
    minHeight: 600,
    title: 'Gchat',
    icon,
    backgroundColor: '#0b1020',
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: true,
    },
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  mainWindow.webContents.on('did-fail-load', async (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
    if (!isMainFrame || errorCode === -3 || !validatedURL || validatedURL.startsWith('file://')) {
      return;
    }
    lastLoadError = {
      errorCode,
      errorDescription,
      url: validatedURL,
      failedAt: new Date().toISOString(),
    };
    await showOfflineScreen();
  });

  mainWindow.webContents.on('did-finish-load', () => {
    const currentUrl = mainWindow?.webContents.getURL() || '';
    if (isHostedUrl(currentUrl)) {
      lastLoadError = null;
    }
  });

  await routeInitialView();

  mainWindow.on('resize', async () => {
    const [w, h] = mainWindow.getSize();
    const c = await getStore();
    c.set('windowBounds', { width: w, height: h });
  });

  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('focus', () => {
    mainWindow.flashFrame(false);
  });
}

// ── System tray ───────────────────────────────────────────────────────────────
async function createTray() {
  const iconPath = getIconPath();
  const trayIcon = nativeImage.createFromPath(iconPath);
  const trayIconSmall = trayIcon.isEmpty()
    ? trayIcon
    : trayIcon.resize({ width: 16, height: 16 });

  tray = new Tray(trayIconSmall);
  tray.setToolTip('Gchat');
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
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

function updateTrayMenu(unread = 0) {
  if (!tray) return;
  const label = unread > 0 ? `Gchat (${unread} unread)` : 'Gchat';
  const contextMenu = Menu.buildFromTemplate([
    { label, enabled: false },
    { type: 'separator' },
    {
      label: 'Open Gchat',
      click: async () => {
        if (!mainWindow) return;
        mainWindow.show();
        mainWindow.focus();
        if (!mainWindow.webContents.getURL()) {
          await routeInitialView();
        }
      },
    },
    {
      label: 'Check for Updates',
      click: () => { autoUpdater.checkForUpdatesAndNotify(); },
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);
  tray.setContextMenu(contextMenu);
  tray.setToolTip(unread > 0 ? `Gchat — ${unread} unread message${unread === 1 ? '' : 's'}` : 'Gchat');
}

// ── IPC handlers (renderer → main) ───────────────────────────────────────────
ipcMain.on('set-unread-count', (_event, count) => {
  const n = Math.max(0, Number(count) || 0);
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setOverlayIcon(
      n > 0 ? createBadgeIcon(n) : null,
      n > 0 ? `${n} unread message${n === 1 ? '' : 's'}` : ''
    );
    if (n > 0 && !mainWindow.isFocused()) {
      mainWindow.flashFrame(true);
    }
  }
  updateTrayMenu(n);
});

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
      if (groupId) mainWindow.webContents.send('focus-group', groupId);
    }
  });
  notif.show();
});

ipcMain.handle('get-launch-at-startup', async () => {
  const cfg = await getStore();
  return !!cfg.get('launchAtStartup');
});

ipcMain.handle('set-launch-at-startup', async (_event, enabled) => {
  const cfg = await getStore();
  const nextValue = !!enabled;
  cfg.set('launchAtStartup', nextValue);
  app.setLoginItemSettings({ openAtLogin: nextValue });
  return nextValue;
});

ipcMain.handle('get-desktop-bootstrap', async () => {
  const cfg = await getStore();
  return {
    serverUrl: OFFICIAL_SERVER_URL,
    launchAtStartup: !!cfg.get('launchAtStartup'),
    onboardingCompleted: !!cfg.get('onboardingCompleted'),
  };
});

ipcMain.handle('check-server-connectivity', async () => {
  let timeout = null;
  try {
    const controller = new AbortController();
    timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(OFFICIAL_SERVER_URL + '/api/auth/csrf', {
      method: 'GET',
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    clearTimeout(timeout);
    return {
      ok: response.ok,
      status: response.status,
      url: OFFICIAL_SERVER_URL,
      checkedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (timeout) clearTimeout(timeout);
    return {
      ok: false,
      url: OFFICIAL_SERVER_URL,
      error: error?.message || 'Unable to connect.',
      checkedAt: new Date().toISOString(),
    };
  }
});

ipcMain.handle('complete-onboarding', async (_event, payload = {}) => {
  const cfg = await getStore();
  const launchAtStartup = !!payload.launchAtStartup;
  cfg.set('serverUrl', OFFICIAL_SERVER_URL);
  cfg.set('launchAtStartup', launchAtStartup);
  cfg.set('onboardingCompleted', true);
  app.setLoginItemSettings({ openAtLogin: launchAtStartup });
  await loadHostedApp();
  return { success: true };
});

ipcMain.handle('retry-connection', async () => {
  await loadHostedApp();
  return true;
});

ipcMain.handle('get-connection-context', async () => ({
  serverUrl: OFFICIAL_SERVER_URL,
  lastLoadError,
}));

// ── Badge icon helper ─────────────────────────────────────────────────────────
function createBadgeIcon(count) {
  const label = count > 99 ? '99+' : String(count);
  const size = 20;
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
  autoUpdater.autoDownload = true;

  autoUpdater.on('update-available', (info) => {
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'Update Available',
      message: `Gchat ${info.version} is downloading in the background.`,
      detail: 'You will be prompted to restart once the update is ready.',
      buttons: ['OK'],
      defaultId: 0,
    }).catch(() => {});
  });

  autoUpdater.on('update-downloaded', () => {
    dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'Update Ready',
      message: 'The latest Gchat update is ready to install.',
      detail: 'Restart Gchat to apply the update now or do it later.',
      buttons: ['Restart Now', 'Later'],
      defaultId: 0,
    }).then(({ response }) => {
      if (response === 0) {
        isQuitting = true;
        autoUpdater.quitAndInstall();
      }
    }).catch(() => {});
  });

  autoUpdater.on('error', (err) => {
    console.error('[updater] error:', err.message);
  });

  if (app.isPackaged) {
    autoUpdater.checkForUpdatesAndNotify().catch(() => {});
  }
}

// ── App lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(async () => {
  const cfg = await getStore();
  cfg.set('serverUrl', OFFICIAL_SERVER_URL);
  app.setLoginItemSettings({ openAtLogin: !!cfg.get('launchAtStartup') });

  await createWindow();
  await createTray();
  setupAutoUpdater();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin' && isQuitting) {
    app.quit();
  }
});

app.on('activate', async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    await createWindow();
  } else if (mainWindow) {
    mainWindow.show();
    mainWindow.focus();
  }
});

app.on('before-quit', () => {
  isQuitting = true;
});
