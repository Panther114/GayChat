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
    return null;
  }
}

/**
 * Encrypt raw bytes (ArrayBuffer) with AES-256-GCM.
 * @param {ArrayBuffer} buffer
 * @param {string} passphrase
 * @param {string} salt — group ID
 * @returns {Promise<{encryptedContent: string, iv: string}>} base64-encoded
 */
async function encryptBytes(buffer, passphrase, salt) {
  const key = await deriveKey(passphrase, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buffer);
  return {
    encryptedContent: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

/**
 * Decrypt AES-256-GCM ciphertext to raw bytes (ArrayBuffer).
 * @param {string} encryptedB64 — base64
 * @param {string} ivB64        — base64
 * @param {string} passphrase
 * @param {string} salt — group ID
 * @returns {Promise<ArrayBuffer|null>} decrypted bytes, or null on failure
 */
async function decryptBytes(encryptedB64, ivB64, passphrase, salt) {
  try {
    const key = await deriveKey(passphrase, salt);
    const iv = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
    const data = Uint8Array.from(atob(encryptedB64), (c) => c.charCodeAt(0));
    return await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  } catch {
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Per-Group Key Storage (localStorage)
// ══════════════════════════════════════════════════════════════════════════════

function getGroupKey(groupId) {
  return localStorage.getItem(`groupKey:${groupId}`) || null;
}

function setGroupKey(groupId, key) {
  localStorage.setItem(`groupKey:${groupId}`, key);
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

// Callback to run after group key is saved
let afterGroupKeySaved = null;

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
    if (!res.ok) {
      if (res.status === 401) window.location.href = 'index.html';
      return;
    }
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
    if (!res.ok) {
      if (res.status === 401) window.location.href = 'index.html';
      console.error('Failed to load messages, status:', res.status);
      return;
    }
    const messages = await res.json();

    for (const msg of messages) {
      await appendMessageBubble(msg);
    }

    // Scroll to bottom
    scrollToBottom();
  } catch (err) {
    console.error('Failed to load messages:', err);
  }
}

/**
 * Build and append a message bubble to the messages area.
 * @param {object} msg — { id, senderId, senderName, senderColor, encryptedContent, iv, type, createdAt }
 */
async function appendMessageBubble(msg) {
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

  if (msg.type === 'image') {
    // Image bubble — attempt async decrypt then update DOM
    const placeholder = document.createElement('div');
    placeholder.className = 'img-locked';
    placeholder.innerHTML = '<span>🔒</span>';
    bubble.appendChild(placeholder);

    const groupKey = currentGroupId ? getGroupKey(currentGroupId) : null;
    if (groupKey) {
      const buf = await decryptBytes(msg.encryptedContent, msg.iv, groupKey, currentGroupId);
      if (buf) {
        const blob = new Blob([buf]);
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img');
        img.src = url;
        img.className = 'msg-image';
        img.addEventListener('click', () => window.open(url, '_blank'));
        bubble.replaceChild(img, placeholder);
      }
    }
  } else {
    // Text bubble — attempt auto-decrypt
    const cipher = document.createElement('span');
    cipher.className = 'msg-cipher';

    const groupKey = currentGroupId ? getGroupKey(currentGroupId) : null;
    if (groupKey) {
      cipher.textContent = '…';
      const plaintext = await decryptMessage(msg.encryptedContent, msg.iv, groupKey, currentGroupId);
      if (plaintext !== null) {
        cipher.textContent = plaintext;
        cipher.classList.add('decrypted');
      } else {
        cipher.textContent = '🔒 ' + truncate(msg.encryptedContent, 40);
      }
    } else {
      cipher.textContent = '🔒 ' + truncate(msg.encryptedContent, 40);
    }
    bubble.appendChild(cipher);
  }

  // Meta row: time
  const meta = document.createElement('div');
  meta.className = 'msg-meta';

  const time = document.createElement('span');
  time.className = 'msg-time';
  time.textContent = formatTime(msg.createdAt);

  meta.appendChild(time);
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

/**
 * Re-render all messages in the current group using the (new) saved key.
 */
async function reRenderMessages() {
  if (!currentGroupId) return;
  await loadMessages(currentGroupId);
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
    if (!res.ok) {
      if (res.status === 401) window.location.href = 'index.html';
      console.error('Failed to load members, status:', res.status);
      return;
    }
    const members = await res.json();

    document.getElementById('chat-member-count').textContent =
      `${members.length} member${members.length !== 1 ? 's' : ''}`;

    const group = groups.find((g) => g.id === groupId);
    const isOwner = group && group.createdBy === currentUser.id;

    // Show/hide disband button
    const disbandBtn = document.getElementById('disband-btn');
    disbandBtn.hidden = !isOwner;

    for (const member of members) {
      const li = document.createElement('li');
      li.className = 'member-item';
      li.dataset.userId = member.id;

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

      if (isOwner && member.id !== currentUser.id) {
        const kickBtn = document.createElement('button');
        kickBtn.className = 'btn-kick';
        kickBtn.textContent = '✕';
        kickBtn.title = `Kick ${member.username}`;
        kickBtn.addEventListener('click', () => kickMember(groupId, member.id, li));
        li.appendChild(kickBtn);
      }

      membersList.appendChild(li);
    }
  } catch (err) {
    console.error('Failed to load members:', err);
  }
}

async function kickMember(groupId, targetUserId, liEl) {
  try {
    const res = await fetch(`/api/groups/${groupId}/members/${targetUserId}`, {
      method: 'DELETE',
      headers: await jsonHeaders(),
    });
    if (!res.ok) {
      const data = await res.json();
      alert(data.error || 'Failed to kick member');
      return;
    }
    // Remove from DOM immediately
    liEl.remove();
    // Decrement member count
    const countEl = document.getElementById('chat-member-count');
    const match = countEl.textContent.match(/\d+/);
    if (match) {
      const newCount = parseInt(match[0], 10) - 1;
      countEl.textContent = `${newCount} member${newCount !== 1 ? 's' : ''}`;
    }
  } catch (err) {
    console.error('Failed to kick member:', err);
  }
}

async function disbandGroup(groupId) {
  if (!confirm('Are you sure you want to disband this group? This will delete all messages and remove all members permanently.')) return;
  try {
    const res = await fetch(`/api/groups/${groupId}`, {
      method: 'DELETE',
      headers: await jsonHeaders(),
    });
    if (!res.ok) {
      const data = await res.json();
      alert(data.error || 'Failed to disband group');
    }
    // Server will emit group_disbanded which handles UI cleanup
  } catch (err) {
    console.error('Failed to disband group:', err);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Socket.IO
// ══════════════════════════════════════════════════════════════════════════════

function initSocket() {
  socket = io({ transports: ['polling', 'websocket'] });

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
  socket.on('new_message', async (msg) => {
    // Only render if the message belongs to the currently viewed group
    if (msg.groupId === currentGroupId) {
      await appendMessageBubble(msg);
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

  // Member kicked
  socket.on('member_kicked', (data) => {
    if (data.userId === currentUser.id) {
      groups = groups.filter((g) => g.id !== data.groupId);
      const item = document.querySelector(`.group-item[data-group-id="${data.groupId}"]`);
      if (item) item.remove();
      if (groups.length === 0) {
        document.getElementById('empty-groups').hidden = false;
      }
      if (currentGroupId === data.groupId) {
        currentGroupId = null;
        document.getElementById('chat-active').hidden = true;
        document.getElementById('chat-empty').hidden = false;
        document.getElementById('right-panel-content').hidden = true;
        document.getElementById('right-panel-empty').hidden = false;
      }
      alert('You were removed from this group.');
    }
  });

  // Group disbanded
  socket.on('group_disbanded', (data) => {
    groups = groups.filter((g) => g.id !== data.groupId);
    const item = document.querySelector(`.group-item[data-group-id="${data.groupId}"]`);
    if (item) item.remove();
    if (groups.length === 0) {
      document.getElementById('empty-groups').hidden = false;
    }
    if (currentGroupId === data.groupId) {
      currentGroupId = null;
      document.getElementById('chat-active').hidden = true;
      document.getElementById('chat-empty').hidden = false;
      document.getElementById('right-panel-content').hidden = true;
      document.getElementById('right-panel-empty').hidden = false;
    }
    alert('This group has been disbanded.');
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
//  Group Key Modal
// ══════════════════════════════════════════════════════════════════════════════

function openGroupKeyModal(callback) {
  afterGroupKeySaved = callback || null;
  const existing = currentGroupId ? getGroupKey(currentGroupId) : '';
  document.getElementById('group-key-input').value = existing || '';
  document.getElementById('group-key-error').textContent = '';
  showModal('group-key-modal');
  setTimeout(() => document.getElementById('group-key-input').focus(), 50);
}

function saveGroupKey() {
  const key = document.getElementById('group-key-input').value;
  if (!key) {
    document.getElementById('group-key-error').textContent = 'Please enter a key';
    return;
  }
  if (!currentGroupId) return;
  setGroupKey(currentGroupId, key);
  hideModal('group-key-modal');
  // Re-render messages with new key
  reRenderMessages();
  if (afterGroupKeySaved) {
    const cb = afterGroupKeySaved;
    afterGroupKeySaved = null;
    cb();
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Send Message Flow
// ══════════════════════════════════════════════════════════════════════════════

async function doSend(text) {
  if (!currentGroupId || !socket) return;
  const key = getGroupKey(currentGroupId);
  if (!key) return; // should not happen; caller checks
  try {
    const { encryptedContent, iv } = await encryptMessage(text, key, currentGroupId);
    socket.emit('send_message', { groupId: currentGroupId, encryptedContent, iv });
    document.getElementById('message-input').value = '';
  } catch (err) {
    console.error('Encryption failed:', err);
  }
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

  // ── Encrypt modal (removed; replaced by group key modal) ────────────────────

  // ── Group key modal ───────────────────────────────────────────────────────
  document.getElementById('group-key-save-btn').addEventListener('click', saveGroupKey);
  document.getElementById('group-key-cancel-btn').addEventListener('click', () => {
    hideModal('group-key-modal');
    afterGroupKeySaved = null;
  });
  document.getElementById('group-key-modal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) {
      hideModal('group-key-modal');
      afterGroupKeySaved = null;
    }
  });
  document.getElementById('group-key-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') saveGroupKey();
  });

  // ── Set key button in right panel ─────────────────────────────────────────
  document.getElementById('set-key-btn').addEventListener('click', () => {
    openGroupKeyModal(null);
  });

  // ── Disband button ────────────────────────────────────────────────────────
  document.getElementById('disband-btn').addEventListener('click', () => {
    if (currentGroupId) disbandGroup(currentGroupId);
  });

  // ── Attach button (image upload) ──────────────────────────────────────────
  document.getElementById('attach-btn').addEventListener('click', () => {
    if (!currentGroupId) return;
    const key = getGroupKey(currentGroupId);
    if (!key) {
      openGroupKeyModal(() => document.getElementById('image-input').click());
      return;
    }
    document.getElementById('image-input').click();
  });

  document.getElementById('image-input').addEventListener('change', handleImageSelect);

  // ── Decrypt modal (removed; replaced by auto-decrypt) ────────────────────

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
//  Handle Send
// ══════════════════════════════════════════════════════════════════════════════

function handleSend() {
  if (!currentGroupId) return;
  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if (!text) return;

  // Stop typing indicator
  clearTimeout(typingTimer);
  if (socket) socket.emit('stop_typing', { groupId: currentGroupId });

  const key = getGroupKey(currentGroupId);
  if (!key) {
    // No key set — open key modal, then auto-send after key is saved
    openGroupKeyModal(() => doSend(text));
    return;
  }
  doSend(text);
}

// ══════════════════════════════════════════════════════════════════════════════
//  Handle Image Upload
// ══════════════════════════════════════════════════════════════════════════════

async function handleImageSelect(e) {
  const file = e.target.files[0];
  // Reset so the same file can be reselected
  e.target.value = '';
  if (!file || !currentGroupId) return;

  const key = getGroupKey(currentGroupId);
  if (!key) return;

  try {
    const buffer = await file.arrayBuffer();
    const { encryptedContent, iv } = await encryptBytes(buffer, key, currentGroupId);

    const headers = await jsonHeaders();
    const res = await fetch(`/api/groups/${currentGroupId}/upload-image`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ encryptedContent, iv }),
    });
    if (!res.ok) {
      const data = await res.json();
      alert(data.error || 'Failed to upload image');
    }
    // Server broadcasts new_message via socket — no need to append manually
  } catch (err) {
    console.error('Image upload failed:', err);
  }
}
