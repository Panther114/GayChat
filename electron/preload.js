'use strict';

/**
 * GayChat Desktop — Electron Preload Script
 *
 * This script runs in a privileged context before the renderer page loads.
 * It uses contextBridge to expose a narrow, safe API surface (electronAPI)
 * to the renderer WITHOUT enabling full Node.js access.
 *
 * Security model:
 *  - contextIsolation: true  — renderer JS cannot access Node / Electron APIs
 *  - nodeIntegration: false  — no require() in renderer
 *  - sandbox: true           — renderer is fully sandboxed
 *  - Only explicitly listed channels are allowed through ipcRenderer
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  /**
   * Notify the main process of the current unread message count.
   * Main process updates the taskbar overlay badge and tray menu.
   * @param {number} count
   */
  setUnreadCount(count) {
    ipcRenderer.send('set-unread-count', count);
  },

  /**
   * Ask the main process to show a native OS notification.
   * Used when the window is hidden or not focused.
   * @param {{ title: string, body: string, groupId?: string }} opts
   */
  showNotification(opts) {
    ipcRenderer.send('show-notification', opts);
  },

  /**
   * Called by the renderer when a specific group should be focused
   * (e.g. after clicking a notification). The main process sends
   * 'focus-group' back, which the renderer listens for.
   * @param {function(groupId: string): void} callback
   */
  onFocusGroup(callback) {
    ipcRenderer.on('focus-group', (_event, groupId) => callback(groupId));
  },

  /**
   * Returns whether the app was launched at startup.
   * @returns {Promise<boolean>}
   */
  getLaunchAtStartup() {
    return ipcRenderer.invoke('get-launch-at-startup');
  },

  /**
   * Enable or disable launch at system startup.
   * @param {boolean} enabled
   * @returns {Promise<boolean>} the new state
   */
  setLaunchAtStartup(enabled) {
    return ipcRenderer.invoke('set-launch-at-startup', enabled);
  },

  /**
   * Get the currently configured server URL.
   * @returns {Promise<string>}
   */
  getServerUrl() {
    return ipcRenderer.invoke('get-server-url');
  },

  /**
   * Change the server URL and reload the window.
   * @param {string} url
   * @returns {Promise<boolean>} true on success, false if URL is invalid
   */
  setServerUrl(url) {
    return ipcRenderer.invoke('set-server-url', url);
  },
});
