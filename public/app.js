/**
 * GayChat — Frontend Application
 * Handles: encryption/decryption, Socket.IO events, UI rendering
 */

'use strict';

// ══════════════════════════════════════════════════════════════════════════════
//  AES-256-GCM Encryption via Web Crypto API (CLIENT-SIDE ONLY)
//  The server never sees plaintext. Only ciphertext + IV are transmitted.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Derive an AES-256 key from a passphrase using PBKDF2.
 * @param {string} passphrase  — user-supplied encryption/decryption key
 * @param {string} salt        — the group UUID (group-scoped key derivation)
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode(salt),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * @param {string} plaintext
 * @param {string} passphrase
 * @param {string} salt — group ID
 * @returns {Promise<{encryptedContent: string, iv: string}>} base64-encoded
 */
async function encryptMessage(plaintext, passphrase, salt) {
  const key = await deriveKey(passphrase, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext)
  );
  return {
    encryptedContent: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * @param {string} encryptedContent — base64
 * @param {string} ivBase64         — base64
 * @param {string} passphrase
 * @param {string} salt — group ID
 * @returns {Promise<string|null>} plaintext, or null on failure (wrong key)
 */
async function decryptMessage(encryptedContent, ivBase64, passphrase, salt) {
  try {
    const key = await deriveKey(passphrase, salt);
    const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0));
    const data = Uint8Array.from(atob(encryptedContent), (c) => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch {
    // Return null on failure so UI can show error
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  App State
// ══════════════════════════════════════════════════════════════════════════════

let currentUser = null;      // { id, username, iconColor }
let currentGroupId = null;   // UUID of the active group
let groups = [];             // array of group objects
let socket = null;
let csrfToken = null;        // CSRF token for state-changing requests

// Typing debounce timer
let typingTimer = null;

// ══════════════════════════════════════════════════════════════════════════════
//  CSRF Helper
// ══════════════════════════════════════════════════════════════════════════════

/** Fetch (or reuse) the CSRF token from the server. */
async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const res = await fetch('/api/auth/csrf');
  const data = await res.json();
  csrfToken = data.csrfToken;
  return csrfToken;
}

/** Build headers for state-changing fetch requests. */
async function jsonHeaders() {
  const token = await getCsrfToken();
  return {
    'Content-Type': 'application/json',
    'X-CSRF-Token': token,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
//  Utility Helpers
// ══════════════════════════════════════════════════════════════════════════════

/** Return first character of a string, uppercased */
function initial(str) {
  return (str || '?')[0].toUpperCase();
}

/** Format ISO date string to HH:MM */
function formatTime(iso) {
  const d = new Date(iso);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  return `${h}:${m}`;
}

/** Truncate a string to maxLen chars */
function truncate(str, maxLen = 60) {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '…';
}

/** Escape HTML to prevent XSS */
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/** Show a modal overlay */
function showModal(id) {
  document.getElementById(id).hidden = false;
}

/** Hide a modal overlay */
function hideModal(id) {
  document.getElementById(id).hidden = true;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Initialization
// ══════════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
  // 1. Check authentication
  try {
    const res = await fetch('/api/auth/me');
    if (res.status === 401) {
      window.location.href = 'index.html';
      return;
    }
    currentUser = await res.json();
  } catch {
    window.location.href = 'index.html';
    return;
  }

  // 2. Set up user avatar in sidebar
  const avatarEl = document.getElementById('user-avatar');
  avatarEl.textContent = initial(currentUser.username);
  avatarEl.style.background = currentUser.iconColor;
  document.getElementById('user-username').textContent = currentUser.username;

  // 3. Load groups
  await loadGroups();

  // 4. Connect Socket.IO
  initSocket();

  // 5. Wire up UI events
  wireEvents();
});

// ══════════════════════════════════════════════════════════════════════════════
//  Groups
// ══════════════════════════════════════════════════════════════════════════════

async function loadGroups() {
  try {
    const res = await fetch('/api/groups/mine');
    groups = await res.json();
    renderGroupList();
  } catch (err) {
    console.error('Failed to load groups:', err);
  }
}

function renderGroupList() {
  const listEl = document.getElementById('group-list');
  const emptyEl = document.getElementById('empty-groups');

  // Clear existing items (but not the empty placeholder)
  listEl.querySelectorAll('.group-item').forEach((el) => el.remove());

  if (groups.length === 0) {
    emptyEl.hidden = false;
    return;
  }
  emptyEl.hidden = true;

  for (const group of groups) {
    const item = buildGroupListItem(group);
    listEl.appendChild(item);
  }
}

function buildGroupListItem(group) {
  const item = document.createElement('div');
  item.className = 'group-item';
  item.dataset.groupId = group.id;
  if (group.id === currentGroupId) item.classList.add('active');

  item.innerHTML = `
    <div class="group-item-icon">${escapeHtml(initial(group.name))}</div>
    <div class="group-item-info">
      <div class="group-item-name">${escapeHtml(group.name)}</div>
      <div class="group-item-sub">(encrypted)</div>
    </div>
  `;

  item.addEventListener('click', () => selectGroup(group.id));
  return item;
}

function addGroupToSidebar(group) {
  groups.push(group);
  const listEl = document.getElementById('group-list');
  document.getElementById('empty-groups').hidden = true;
  listEl.appendChild(buildGroupListItem(group));
}

// ══════════════════════════════════════════════════════════════════════════════
//  Select / Switch Group
// ══════════════════════════════════════════════════════════════════════════════

async function selectGroup(groupId) {
  currentGroupId = groupId;
  const group = groups.find((g) => g.id === groupId);
  if (!group) return;

  // Highlight active item in sidebar
  document.querySelectorAll('.group-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.groupId === groupId);
  });

  // Show chat area, hide empty state
  document.getElementById('chat-empty').hidden = true;
  document.getElementById('chat-active').hidden = false;
  document.getElementById('right-panel-empty').hidden = true;
  document.getElementById('right-panel-content').hidden = false;

  // Update top bar
  document.getElementById('chat-group-name').textContent = group.name;
  document.getElementById('right-group-name').textContent = group.name;
  document.getElementById('right-group-code').textContent = group.code;

  // Load messages
  await loadMessages(groupId);

  // Load members
  await loadMembers(groupId);

  // Join Socket.IO room
  if (socket) {
    socket.emit('join_room', groupId);
  }

  // Hide typing indicator when switching groups
  hideTypingIndicator();

  // On mobile, close sidebar after selecting
  closeSidebarMobile();
}

// ══════════════════════════════════════════════════════════════════════════════
//  Messages
// ══════════════════════════════════════════════════════════════════════════════

async function loadMessages(groupId) {
  const messagesArea = document.getElementById('messages-area');
  messagesArea.innerHTML = '';

  try {
    const res = await fetch(`/api/groups/${groupId}/messages`);
    const messages = await res.json();

    for (const msg of messages) {
      appendMessageBubble(msg);
    }

    // Scroll to bottom
    scrollToBottom();
  } catch (err) {
    console.error('Failed to load messages:', err);
  }
}

/**
 * Build and append a message bubble to the messages area.
 * @param {object} msg — { id, senderId, senderName, senderColor, encryptedContent, iv, createdAt }
 */
function appendMessageBubble(msg) {
  const isOwn = msg.senderId === currentUser.id;
  const messagesArea = document.getElementById('messages-area');

  const row = document.createElement('div');
  row.className = `msg-row ${isOwn ? 'own' : 'other'}`;
  row.dataset.msgId = msg.id;

  // Avatar
  const avatar = document.createElement('div');
  avatar.className = 'avatar';
  avatar.textContent = initial(msg.senderName);
  avatar.style.background = msg.senderColor || '#4A90D9';

  // Content wrapper
  const content = document.createElement('div');
  content.className = 'msg-content';

  // Sender name (only for others' messages)
  if (!isOwn) {
    const sender = document.createElement('div');
    sender.className = 'msg-sender';
    sender.textContent = msg.senderName;
    content.appendChild(sender);
  }

  // Bubble
  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';

  // Ciphertext display (truncated)
  const cipher = document.createElement('span');
  cipher.className = 'msg-cipher';
  cipher.textContent = truncate(msg.encryptedContent, 60);
  bubble.appendChild(cipher);

  // Meta row: time + decrypt button
  const meta = document.createElement('div');
  meta.className = 'msg-meta';

  const time = document.createElement('span');
  time.className = 'msg-time';
  time.textContent = formatTime(msg.createdAt);

  const decryptBtn = document.createElement('button');
  decryptBtn.className = 'btn-decrypt';
  decryptBtn.textContent = '🔓';
  decryptBtn.title = 'Decrypt this message';
  decryptBtn.addEventListener('click', () => {
    openDecryptModal(msg.encryptedContent, msg.iv, cipher, decryptBtn);
  });

  meta.appendChild(time);
  meta.appendChild(decryptBtn);

  bubble.appendChild(meta);
  content.appendChild(bubble);

  if (isOwn) {
    row.appendChild(content);
    row.appendChild(avatar);
  } else {
    row.appendChild(avatar);
    row.appendChild(content);
  }

  messagesArea.appendChild(row);
}

function scrollToBottom() {
  const area = document.getElementById('messages-area');
  area.scrollTop = area.scrollHeight;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Members
// ══════════════════════════════════════════════════════════════════════════════

async function loadMembers(groupId) {
  const membersList = document.getElementById('members-list');
  membersList.innerHTML = '';

  try {
    const res = await fetch(`/api/groups/${groupId}/members`);
    const members = await res.json();

    document.getElementById('chat-member-count').textContent =
      `${members.length} member${members.length !== 1 ? 's' : ''}`;

    for (const member of members) {
      const li = document.createElement('li');
      li.className = 'member-item';

      const avatar = document.createElement('div');
      avatar.className = 'avatar';
      avatar.style.width = '28px';
      avatar.style.height = '28px';
      avatar.style.fontSize = '13px';
      avatar.style.background = member.iconColor || '#4A90D9';
      avatar.textContent = initial(member.username);

      const name = document.createElement('span');
      name.className = 'member-name';
      name.textContent = member.username;

      li.appendChild(avatar);
      li.appendChild(name);
      membersList.appendChild(li);
    }
  } catch (err) {
    console.error('Failed to load members:', err);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Socket.IO
// ══════════════════════════════════════════════════════════════════════════════

function initSocket() {
  socket = io({ transports: ['websocket', 'polling'] });

  socket.on('connect', () => {
    console.log('Socket connected');
    // Re-join current room if already selected
    if (currentGroupId) {
      socket.emit('join_room', currentGroupId);
    }
  });

  socket.on('disconnect', () => {
    console.log('Socket disconnected');
  });

  // Incoming message
  socket.on('new_message', (msg) => {
    // Only render if the message belongs to the currently viewed group
    if (msg.groupId === currentGroupId) {
      appendMessageBubble(msg);
      scrollToBottom();
    }
  });

  // Typing indicators
  socket.on('user_typing', ({ username }) => {
    showTypingIndicator(username);
  });

  socket.on('user_stop_typing', () => {
    hideTypingIndicator();
  });

  socket.on('error', ({ message }) => {
    console.error('Socket error:', message);
  });
}

function showTypingIndicator(username) {
  const indicator = document.getElementById('typing-indicator');
  document.getElementById('typing-user').textContent = `${username} is typing`;
  indicator.hidden = false;
}

function hideTypingIndicator() {
  document.getElementById('typing-indicator').hidden = true;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Send Message Flow
// ══════════════════════════════════════════════════════════════════════════════

let pendingPlaintext = null; // text waiting for encryption key

function openEncryptModal(plaintext) {
  pendingPlaintext = plaintext;
  document.getElementById('encrypt-key').value = '';
  document.getElementById('encrypt-error').textContent = '';
  showModal('encrypt-modal');
  // Focus key input
  setTimeout(() => document.getElementById('encrypt-key').focus(), 50);
}

async function confirmEncryptAndSend() {
  const key = document.getElementById('encrypt-key').value;
  if (!key) {
    document.getElementById('encrypt-error').textContent = 'Please enter an encryption key';
    return;
  }
  if (!pendingPlaintext || !currentGroupId) return;

  try {
    const { encryptedContent, iv } = await encryptMessage(
      pendingPlaintext,
      key,
      currentGroupId
    );

    socket.emit('send_message', {
      groupId: currentGroupId,
      encryptedContent,
      iv,
    });

    hideModal('encrypt-modal');
    document.getElementById('message-input').value = '';
    pendingPlaintext = null;
  } catch (err) {
    document.getElementById('encrypt-error').textContent = 'Encryption failed: ' + err.message;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Decrypt Message Flow
// ══════════════════════════════════════════════════════════════════════════════

let pendingDecrypt = null; // { encryptedContent, iv, cipherEl, btnEl }

function openDecryptModal(encryptedContent, iv, cipherEl, btnEl) {
  pendingDecrypt = { encryptedContent, iv, cipherEl, btnEl };
  document.getElementById('decrypt-key').value = '';
  document.getElementById('decrypt-error').textContent = '';
  showModal('decrypt-modal');
  setTimeout(() => document.getElementById('decrypt-key').focus(), 50);
}

async function confirmDecrypt() {
  const key = document.getElementById('decrypt-key').value;
  if (!key) {
    document.getElementById('decrypt-error').textContent = 'Please enter a decryption key';
    return;
  }
  if (!pendingDecrypt || !currentGroupId) return;

  const { encryptedContent, iv, cipherEl, btnEl } = pendingDecrypt;

  const plaintext = await decryptMessage(encryptedContent, iv, key, currentGroupId);

  if (plaintext === null) {
    document.getElementById('decrypt-error').textContent = '❌ Wrong key — decryption failed';
    return;
  }

  // Success: replace ciphertext with plaintext
  cipherEl.textContent = plaintext;
  cipherEl.classList.add('decrypted');
  btnEl.textContent = '🔑';
  btnEl.title = 'Decrypted';
  // Disable further decryption attempts on this bubble
  btnEl.disabled = true;
  btnEl.style.opacity = '0.5';

  hideModal('decrypt-modal');
  pendingDecrypt = null;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Create / Join Group
// ══════════════════════════════════════════════════════════════════════════════

async function createGroup() {
  const name = document.getElementById('create-group-name').value.trim();
  const code = document.getElementById('create-group-code').value.trim();
  const errorEl = document.getElementById('create-error');
  errorEl.textContent = '';

  if (!name || !code) {
    errorEl.textContent = 'Both name and code are required';
    return;
  }

  try {
    const res = await fetch('/api/groups/create', {
      method: 'POST',
      headers: await jsonHeaders(),
      body: JSON.stringify({ name, code }),
    });
    const data = await res.json();
    if (!res.ok) {
      errorEl.textContent = data.error || 'Failed to create group';
      return;
    }

    hideModal('create-modal');
    document.getElementById('create-group-name').value = '';
    document.getElementById('create-group-code').value = '';

    addGroupToSidebar(data);
    selectGroup(data.id);
  } catch {
    errorEl.textContent = 'Network error. Please try again.';
  }
}

async function joinGroup() {
  const code = document.getElementById('join-group-code').value.trim();
  const errorEl = document.getElementById('join-error');
  errorEl.textContent = '';

  if (!code) {
    errorEl.textContent = 'Please enter a group code';
    return;
  }

  try {
    const res = await fetch('/api/groups/join', {
      method: 'POST',
      headers: await jsonHeaders(),
      body: JSON.stringify({ code }),
    });
    const data = await res.json();
    if (!res.ok) {
      errorEl.textContent = data.error || 'Failed to join group';
      return;
    }

    hideModal('join-modal');
    document.getElementById('join-group-code').value = '';

    // Only add if not already in the list
    if (!groups.find((g) => g.id === data.id)) {
      addGroupToSidebar(data);
    }
    selectGroup(data.id);
  } catch {
    errorEl.textContent = 'Network error. Please try again.';
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Mobile Sidebar
// ══════════════════════════════════════════════════════════════════════════════

function openSidebarMobile() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-overlay').hidden = false;
}

function closeSidebarMobile() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').hidden = true;
}

// ══════════════════════════════════════════════════════════════════════════════
//  Wire All UI Events
// ══════════════════════════════════════════════════════════════════════════════

function wireEvents() {
  // ── Logout ────────────────────────────────────────────────────────────────
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: await jsonHeaders(),
    });
    window.location.href = 'index.html';
  });

  // ── New Group button ──────────────────────────────────────────────────────
  document.getElementById('new-group-btn').addEventListener('click', () => {
    document.getElementById('create-error').textContent = '';
    document.getElementById('create-group-name').value = '';
    document.getElementById('create-group-code').value = '';
    showModal('create-modal');
    setTimeout(() => document.getElementById('create-group-name').focus(), 50);
  });

  document.getElementById('create-confirm-btn').addEventListener('click', createGroup);
  document.getElementById('create-cancel-btn').addEventListener('click', () =>
    hideModal('create-modal')
  );
  // Close create modal on overlay click
  document.getElementById('create-modal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) hideModal('create-modal');
  });
  // Keyboard: Enter to confirm
  document.getElementById('create-group-code').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') createGroup();
  });

  // ── Join Group button ─────────────────────────────────────────────────────
  document.getElementById('join-group-btn').addEventListener('click', () => {
    document.getElementById('join-error').textContent = '';
    document.getElementById('join-group-code').value = '';
    showModal('join-modal');
    setTimeout(() => document.getElementById('join-group-code').focus(), 50);
  });

  document.getElementById('join-confirm-btn').addEventListener('click', joinGroup);
  document.getElementById('join-cancel-btn').addEventListener('click', () =>
    hideModal('join-modal')
  );
  document.getElementById('join-modal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) hideModal('join-modal');
  });
  document.getElementById('join-group-code').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') joinGroup();
  });

  // ── Send message ──────────────────────────────────────────────────────────
  document.getElementById('send-btn').addEventListener('click', handleSend);
  document.getElementById('message-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  });

  // ── Typing events ─────────────────────────────────────────────────────────
  document.getElementById('message-input').addEventListener('input', () => {
    if (!currentGroupId || !socket) return;
    socket.emit('typing', { groupId: currentGroupId });

    // Reset debounce timer
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
      socket.emit('stop_typing', { groupId: currentGroupId });
    }, 2000);
  });

  document.getElementById('message-input').addEventListener('blur', () => {
    if (!currentGroupId || !socket) return;
    clearTimeout(typingTimer);
    socket.emit('stop_typing', { groupId: currentGroupId });
  });

  // ── Encrypt modal ─────────────────────────────────────────────────────────
  document.getElementById('encrypt-confirm-btn').addEventListener('click', confirmEncryptAndSend);
  document.getElementById('encrypt-cancel-btn').addEventListener('click', () => {
    hideModal('encrypt-modal');
    pendingPlaintext = null;
  });
  document.getElementById('encrypt-modal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) {
      hideModal('encrypt-modal');
      pendingPlaintext = null;
    }
  });
  document.getElementById('encrypt-key').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') confirmEncryptAndSend();
  });

  // ── Decrypt modal ─────────────────────────────────────────────────────────
  document.getElementById('decrypt-confirm-btn').addEventListener('click', confirmDecrypt);
  document.getElementById('decrypt-cancel-btn').addEventListener('click', () => {
    hideModal('decrypt-modal');
    pendingDecrypt = null;
  });
  document.getElementById('decrypt-modal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) {
      hideModal('decrypt-modal');
      pendingDecrypt = null;
    }
  });
  document.getElementById('decrypt-key').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') confirmDecrypt();
  });

  // ── Copy group code ───────────────────────────────────────────────────────
  document.getElementById('copy-code-btn').addEventListener('click', () => {
    const code = document.getElementById('right-group-code').textContent;
    if (!code || code === '—') return;
    navigator.clipboard.writeText(code).then(() => {
      const btn = document.getElementById('copy-code-btn');
      btn.textContent = '✅';
      setTimeout(() => (btn.textContent = '📋'), 1500);
    });
  });

  // ── Mobile sidebar toggle ─────────────────────────────────────────────────
  document.getElementById('sidebar-toggle').addEventListener('click', openSidebarMobile);
  document.getElementById('sidebar-overlay').addEventListener('click', closeSidebarMobile);
}

// ══════════════════════════════════════════════════════════════════════════════
//  Handle Send (opens encrypt modal)
// ══════════════════════════════════════════════════════════════════════════════

function handleSend() {
  if (!currentGroupId) return;
  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if (!text) return;

  // Stop typing indicator before opening modal
  clearTimeout(typingTimer);
  if (socket) socket.emit('stop_typing', { groupId: currentGroupId });

  openEncryptModal(text);
}
