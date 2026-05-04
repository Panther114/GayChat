'use strict';

const stepPanels = Array.from(document.querySelectorAll('.step-panel'));
const stepItems = Array.from(document.querySelectorAll('.step-item'));
const nextBtn = document.getElementById('next-btn');
const backBtn = document.getElementById('back-btn');
const stepNote = document.getElementById('step-note');
const launchAtStartupCheckbox = document.getElementById('launch-at-startup');
const serverUrlEl = document.getElementById('server-url');
const summaryUrlEl = document.getElementById('summary-url');
const summaryStartupEl = document.getElementById('summary-startup');
const summaryNotificationsEl = document.getElementById('summary-notifications');
const connectivityPill = document.getElementById('connectivity-pill');
const connectivityMeta = document.getElementById('connectivity-meta');
const connectivityMessage = document.getElementById('connectivity-message');
const notificationPill = document.getElementById('notification-pill');
const notificationMeta = document.getElementById('notification-meta');
const notificationMessage = document.getElementById('notification-message');
const recheckBtn = document.getElementById('recheck-btn');
const notificationBtn = document.getElementById('notification-btn');

const state = {
  currentStep: 0,
  serverUrl: '',
  connectivityOk: false,
  checkingConnectivity: false,
  notificationPermission: typeof Notification === 'undefined' ? 'unsupported' : Notification.permission,
  finishing: false,
};

function setPill(el, type, text) {
  el.className = 'status-pill' + (type ? ' ' + type : '');
  el.textContent = text;
}

function updateNotificationStatus() {
  const permission = typeof Notification === 'undefined' ? 'unsupported' : Notification.permission;
  state.notificationPermission = permission;

  if (permission === 'granted') {
    setPill(notificationPill, 'success', 'Allowed');
    notificationMeta.textContent = 'Windows can show native Gchat alerts.';
    notificationMessage.textContent = 'You will receive native desktop notifications, unread badge updates, and click-to-focus behavior.';
    notificationBtn.textContent = 'Notification access granted';
    notificationBtn.disabled = true;
    return;
  }

  if (permission === 'denied') {
    setPill(notificationPill, 'warning', 'Blocked');
    notificationMeta.textContent = 'Notifications are blocked for this app session.';
    notificationMessage.textContent = 'You can continue setup, but native alerts will stay disabled until Windows/browser permissions are changed.';
    notificationBtn.textContent = 'Blocked by system settings';
    notificationBtn.disabled = true;
    return;
  }

  if (permission === 'unsupported') {
    setPill(notificationPill, 'warning', 'Unavailable');
    notificationMeta.textContent = 'Notification APIs are not available here.';
    notificationMessage.textContent = 'Setup can continue, but the desktop shell will not be able to prompt for alerts from this screen.';
    notificationBtn.textContent = 'Not supported';
    notificationBtn.disabled = true;
    return;
  }

  setPill(notificationPill, '', 'Not requested yet');
  notificationMeta.textContent = 'Windows permission status';
  notificationMessage.textContent = 'Allow notifications so Gchat can alert you about new messages even when the window is hidden.';
  notificationBtn.textContent = 'Request notification access';
  notificationBtn.disabled = false;
}

async function runConnectivityCheck() {
  if (state.checkingConnectivity) return;
  state.checkingConnectivity = true;
  setPill(connectivityPill, '', 'Checking…');
  connectivityMeta.textContent = 'Contacting the Railway deployment.';
  connectivityMessage.textContent = 'Please wait while Gchat confirms the hosted server is reachable.';
  recheckBtn.disabled = true;
  nextBtn.disabled = true;

  try {
    const result = await window.electronAPI.getDesktopBootstrap();
    state.serverUrl = result.serverUrl;
    serverUrlEl.textContent = result.serverUrl;
    summaryUrlEl.textContent = result.serverUrl;
  } catch {
    // ignore bootstrap refresh failure here
  }

  try {
    const result = await window.electronAPI.checkServerConnectivity();
    state.connectivityOk = !!result.ok;
    if (result.ok) {
      setPill(connectivityPill, 'success', 'Connected');
      connectivityMeta.textContent = `Railway responded${result.status ? ' with HTTP ' + result.status : ''}.`;
      connectivityMessage.textContent = 'Setup can continue. Gchat will open the hosted sign-in screen after you finish the wizard.';
    } else {
      setPill(connectivityPill, 'error', 'Unavailable');
      connectivityMeta.textContent = result.error || 'No successful response received.';
      connectivityMessage.textContent = 'Gchat is online-only for this build, so setup cannot continue until the hosted app responds.';
    }
  } catch (error) {
    state.connectivityOk = false;
    setPill(connectivityPill, 'error', 'Unavailable');
    connectivityMeta.textContent = error?.message || 'Connectivity check failed.';
    connectivityMessage.textContent = 'Gchat is online-only for this build, so setup cannot continue until the hosted app responds.';
  } finally {
    state.checkingConnectivity = false;
    recheckBtn.disabled = false;
    syncStepUI();
  }
}

function syncSummary() {
  summaryStartupEl.textContent = launchAtStartupCheckbox.checked ? 'Yes — launch the desktop shell with Windows' : 'No — start Gchat manually';
  summaryNotificationsEl.textContent = state.notificationPermission === 'granted'
    ? 'Allowed'
    : state.notificationPermission === 'denied'
      ? 'Blocked in system settings'
      : state.notificationPermission === 'unsupported'
        ? 'Unsupported on this system'
        : 'Not requested yet';
}

function syncStepUI() {
  stepPanels.forEach((panel, index) => {
    panel.classList.toggle('active', index === state.currentStep);
  });

  stepItems.forEach((item, index) => {
    item.classList.toggle('active', index === state.currentStep);
    item.classList.toggle('complete', index < state.currentStep);
  });

  backBtn.disabled = state.currentStep === 0 || state.finishing;
  stepNote.textContent = `Step ${state.currentStep + 1} of ${stepPanels.length}`;

  if (state.currentStep === 1) {
    nextBtn.disabled = !state.connectivityOk || state.checkingConnectivity || state.finishing;
  } else {
    nextBtn.disabled = state.finishing;
  }

  if (state.currentStep === stepPanels.length - 1) {
    nextBtn.textContent = state.finishing ? 'Opening Gchat…' : 'Finish setup';
  } else {
    nextBtn.textContent = 'Next';
  }

  syncSummary();
}

async function requestNotifications() {
  if (typeof Notification === 'undefined' || Notification.permission !== 'default') {
    updateNotificationStatus();
    return;
  }

  notificationBtn.disabled = true;
  notificationBtn.textContent = 'Requesting…';
  try {
    await Notification.requestPermission();
  } catch {
    // ignore and let status refresh below
  } finally {
    updateNotificationStatus();
    syncSummary();
  }
}

async function finishSetup() {
  if (state.finishing) return;
  state.finishing = true;
  syncStepUI();
  try {
    await window.electronAPI.completeOnboarding({
      launchAtStartup: launchAtStartupCheckbox.checked,
    });
  } catch (error) {
    state.finishing = false;
    syncStepUI();
    alert(error?.message || 'Unable to finish setup. Please try again.');
  }
}

nextBtn.addEventListener('click', async () => {
  if (state.currentStep === stepPanels.length - 1) {
    await finishSetup();
    return;
  }
  state.currentStep += 1;
  syncStepUI();
  if (state.currentStep === 1 && !state.connectivityOk) {
    await runConnectivityCheck();
  }
});

backBtn.addEventListener('click', () => {
  if (state.currentStep === 0 || state.finishing) return;
  state.currentStep -= 1;
  syncStepUI();
});

recheckBtn.addEventListener('click', runConnectivityCheck);
notificationBtn.addEventListener('click', requestNotifications);
launchAtStartupCheckbox.addEventListener('change', syncSummary);

window.addEventListener('DOMContentLoaded', async () => {
  updateNotificationStatus();
  try {
    const bootstrap = await window.electronAPI.getDesktopBootstrap();
    state.serverUrl = bootstrap.serverUrl;
    serverUrlEl.textContent = bootstrap.serverUrl;
    summaryUrlEl.textContent = bootstrap.serverUrl;
    launchAtStartupCheckbox.checked = !!bootstrap.launchAtStartup;
  } catch {
    serverUrlEl.textContent = 'https://gchat.up.railway.app';
    summaryUrlEl.textContent = 'https://gchat.up.railway.app';
  }
  syncSummary();
  syncStepUI();
});
