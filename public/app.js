'use strict';

// ── Crypto Helpers ───────────────────────────────────────────────────────────

// Cache derived keys to avoid running 100 000 PBKDF2 iterations for every
// individual message encrypt/decrypt operation (#21).
const derivedKeyCache = new Map(); // `${passphrase}\x00${groupId}` -> CryptoKey

async function deriveKey(passphrase, groupId) {
  const cacheKey = passphrase + '\x00' + groupId;
  if (derivedKeyCache.has(cacheKey)) return derivedKeyCache.get(cacheKey);
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(groupId), iterations: 100000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  derivedKeyCache.set(cacheKey, key);
  return key;
}

// Convert a Uint8Array to a base64 string without using spread (which blows
// the call stack for large buffers, #1).
function uint8ToBase64(bytes) {
  let binary = '';
  const CHUNK = 32768;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

async function encryptMessage(text, passphrase, groupId) {
  const key = await deriveKey(passphrase, groupId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const buf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  return {
    encryptedContent: uint8ToBase64(new Uint8Array(buf)),
    iv: uint8ToBase64(iv),
  };
}

async function decryptMessage(encryptedContent, ivB64, passphrase, groupId) {
  try {
    const key = await deriveKey(passphrase, groupId);
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const buf = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, buf);
    return new TextDecoder().decode(dec);
  } catch {
    return null;
  }
}

async function encryptBytes(buffer, passphrase, groupId) {
  const key = await deriveKey(passphrase, groupId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buffer);
  return {
    encryptedContent: uint8ToBase64(new Uint8Array(encrypted)),
    iv: uint8ToBase64(iv),
  };
}

async function decryptBytes(encryptedContent, ivB64, passphrase, groupId) {
  try {
    const key = await deriveKey(passphrase, groupId);
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const buf = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
    return await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, buf);
  } catch {
    return null;
  }
}

// ── Image MIME type detection ──────────────────────────────────────────────────
function detectImageMime(buf) {
  const ab = buf instanceof ArrayBuffer ? buf : buf.buffer;
  const bytes = new Uint8Array(ab, 0, Math.min(12, ab.byteLength));
  if (bytes[0] === 0xFF && bytes[1] === 0xD8) return 'image/jpeg';
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'image/png';
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return 'image/gif';
  // WebP: 'RIFF' at 0 + 'WEBP' at 8
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'image/webp';
  return null;
}

// ── Compression Helper ────────────────────────────────────────────────────────
async function compressImage(file) {
  return new Promise((resolve) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const MAX = 1200;
      let w = img.naturalWidth, h = img.naturalHeight;
      if (w > MAX || h > MAX) {
        if (w > h) { h = Math.round(h * MAX / w); w = MAX; }
        else { w = Math.round(w * MAX / h); h = MAX; }
      }
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      canvas.getContext('2d').drawImage(img, 0, 0, w, h);
      canvas.toBlob(blob => resolve(blob), 'image/jpeg', 0.75);
    };
    img.onerror = () => { URL.revokeObjectURL(url); resolve(file); };
    img.src = url;
  });
}

// ── CSRF ──────────────────────────────────────────────────────────────────────
let csrfToken = null;
async function fetchCsrfToken() {
  try {
    const r = await fetch('/api/auth/csrf');
    const d = await r.json();
    csrfToken = d.csrfToken;
  } catch { /* will retry */ }
}

function apiHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (csrfToken) h['X-CSRF-Token'] = csrfToken;
  return h;
}

// ── Per-group key storage ────────────────────────────────────────────────────
function getGroupKey(groupId) { return localStorage.getItem('gk:' + groupId) || null; }
function setGroupKey(groupId, key) { localStorage.setItem('gk:' + groupId, key); }
function clearGroupKey(groupId) {
  // Evict the cached CryptoKey so re-entry uses a fresh derivation
  const old = localStorage.getItem('gk:' + groupId);
  if (old) derivedKeyCache.delete(old + '\x00' + groupId);
  localStorage.removeItem('gk:' + groupId);
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function truncate(s, n) { return s && s.length > n ? s.slice(0, n) + '…' : s; }
function formatTime(iso) {
  if (!iso) return '';
  // SQLite CURRENT_TIMESTAMP returns 'YYYY-MM-DD HH:MM:SS' (no T, no Z).
  // Normalize to a proper UTC ISO string before parsing so all browsers
  // treat it as UTC rather than local time.
  const str = iso.replace(' ', 'T');
  const utc = (str.endsWith('Z') || str.includes('+')) ? str : str + 'Z';
  return new Date(utc).toLocaleTimeString('zh-CN', {
    timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', hour12: false,
  });
}

// ── Audio: notification sound via Web Audio ──────────────────────────────────
let audioCtx = null;
function playNotifSound() {
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain); gain.connect(audioCtx.destination);
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.18);
    osc.start(); osc.stop(audioCtx.currentTime + 0.18);
  } catch { /* audio not available */ }
}

// ── Page title notification ──────────────────────────────────────────────────
function updatePageTitleNotification() {
  if (unreadNotificationCount > 0) {
    if (!titleBlinkInterval) {
      let showingNotif = true;
      titleBlinkInterval = setInterval(() => {
        if (showingNotif) {
          document.title = `(${unreadNotificationCount}) New ${unreadNotificationCount === 1 ? 'message' : 'messages'}`;
        } else {
          document.title = originalPageTitle;
        }
        showingNotif = !showingNotif;
      }, 1500);
    }
  } else {
    if (titleBlinkInterval) {
      clearInterval(titleBlinkInterval);
      titleBlinkInterval = null;
    }
    document.title = originalPageTitle;
  }
}

function clearPageTitleNotification() {
  unreadNotificationCount = 0;
  updatePageTitleNotification();
}

// ── Image Viewer ──────────────────────────────────────────────────────────────
function showImageViewer(imageUrl) {
  const modal = $('image-viewer-modal');
  const img = $('image-viewer-img');
  img.src = imageUrl;
  modal.hidden = false;
}

function hideImageViewer() {
  const modal = $('image-viewer-modal');
  const img = $('image-viewer-img');
  modal.hidden = true;
  img.src = '';
}

// ── State ─────────────────────────────────────────────────────────────────────
let currentUser = null;
let currentGroupId = null;
let currentGroupData = null;
let groups = [];
let members = [];
let socket = null;
let encryptionVisible = true;
let messageMode = 'normal'; // 'normal' | 'whisper'
let whisperRecipients = [];
let replyingTo = null;
let unreadCounts = {};
let scrollUnreadCount = 0;
let onlineUsers = new Set();
let allMessages = [];
let oldestMessageId = null;
let loadingOlder = false;
let clientRateLimiter = { times: [], lastContent: '', repeatCount: 0 };
let originalPageTitle = 'GayChat 🏳️‍🌈';
let unreadNotificationCount = 0;
let titleBlinkInterval = null;

// Decryption failure text constants (must match renderMsgContent output)
const MSG_NO_KEY = '[No key — set group key to decrypt]';
const MSG_DECRYPT_FAIL = '[Unable to decrypt]';

// Scroll threshold (px from top) that triggers loading older messages
const SCROLL_LOAD_THRESHOLD = 1;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const messagesArea = () => $('messages-area');

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await fetchCsrfToken();
  try {
    const res = await fetch('/api/auth/me');
    if (res.status === 401) { window.location.href = 'index.html'; return; }
    if (!res.ok) throw new Error();
    currentUser = await res.json();
  } catch {
    window.location.href = 'index.html'; return;
  }

  // Set user display
  $('user-username').textContent = currentUser.username;
  const ua = $('user-avatar');
  if (currentUser.profilePicture) {
    ua.style.background = 'none';
    const img = document.createElement('img');
    img.src = currentUser.profilePicture;
    img.style.width = '100%'; img.style.height = '100%'; img.style.objectFit = 'cover'; img.style.borderRadius = '50%';
    ua.appendChild(img);
  } else {
    ua.textContent = currentUser.username[0].toUpperCase();
    ua.style.background = currentUser.iconColor;
  }

  await loadGroups();
  initSocket();
  setupEventListeners();
  setupEmojiPicker();
  setupKeyboardShortcuts();

  // Clear page title notification when page is focused
  window.addEventListener('focus', clearPageTitleNotification);
  window.addEventListener('blur', () => {
    // Start tracking unread when page loses focus
  });
});

// ── Load groups ───────────────────────────────────────────────────────────────
async function loadGroups() {
  try {
    const res = await fetch('/api/groups/mine');
    if (!res.ok) return;
    groups = await res.json();
    renderGroupList();
  } catch(err) { console.error('loadGroups error:', err); }
}

function renderGroupList() {
  const list = $('group-list');
  const empty = $('empty-groups');
  list.innerHTML = '';
  list.appendChild(empty);
  if (groups.length === 0) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  for (const g of groups) {
    list.appendChild(buildGroupItem(g));
  }
}

function buildGroupItem(g) {
  const item = document.createElement('div');
  item.className = 'group-item' + (g.id === currentGroupId ? ' active' : '');
  item.dataset.groupId = g.id;

  const av = document.createElement('div');
  av.className = 'group-item-avatar';
  av.style.background = '#' + Math.abs(hashCode(g.name)).toString(16).slice(0,6).padStart(6,'5');
  av.textContent = g.name[0].toUpperCase();

  const info = document.createElement('div');
  info.className = 'group-item-info';

  const name = document.createElement('div');
  name.className = 'group-item-name';
  name.textContent = g.name;

  const preview = document.createElement('div');
  preview.className = 'group-item-preview';
  preview.id = 'preview-' + g.id;
  preview.textContent = g._lastPreview || '';

  info.append(name, preview);

  const badge = document.createElement('span');
  badge.className = 'group-item-badge';
  badge.id = 'badge-' + g.id;
  const cnt = unreadCounts[g.id] || 0;
  badge.textContent = cnt;
  badge.hidden = cnt === 0;

  item.append(av, info, badge);
  item.addEventListener('click', () => selectGroup(g.id));
  return item;
}

function hashCode(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = Math.imul(31, h) + s.charCodeAt(i);
  return h;
}

function updateGroupPreview(groupId, text, time) {
  const el = $('preview-' + groupId);
  if (el) el.textContent = (time ? formatTime(time) + ' ' : '') + truncate(text, 35);
  const g = groups.find(x => x.id === groupId);
  if (g) g._lastPreview = (time ? formatTime(time) + ' ' : '') + truncate(text, 35);
}

function updateUnreadBadge(groupId, count) {
  const badge = $('badge-' + groupId);
  if (!badge) return;
  badge.textContent = count;
  badge.hidden = count === 0;
}

// ── Select group ──────────────────────────────────────────────────────────────
async function selectGroup(groupId) {
  currentGroupId = groupId;
  currentGroupData = groups.find(g => g.id === groupId) || null;
  allMessages = [];
  oldestMessageId = null;
  replyingTo = null;
  whisperRecipients = [];
  messageMode = 'normal';
  updateWhisperBtn();

  // Reset unread for this group
  unreadCounts[groupId] = 0;
  updateUnreadBadge(groupId, 0);
  scrollUnreadCount = 0;
  updateScrollBadge();

  // Update sidebar active state
  document.querySelectorAll('.group-item').forEach(el => {
    el.classList.toggle('active', el.dataset.groupId === groupId);
  });

  // Show chat area
  $('chat-empty').hidden = true;
  $('chat-active').hidden = false;
  $('reply-preview-bar').hidden = true;

  // Set header
  $('chat-group-name').textContent = currentGroupData ? currentGroupData.name : '';
  $('right-group-name').textContent = currentGroupData ? currentGroupData.name : '';
  $('right-group-code').textContent = currentGroupData ? currentGroupData.code : '';
  $('right-panel-content').hidden = false;
  $('right-panel-empty').hidden = true;

  // Owner controls
  const isOwner = currentGroupData && currentGroupData.createdBy === currentUser.id;
  $('owner-actions').hidden = !isOwner;
  $('member-actions').hidden = isOwner;
  // Show clear history button if owner OR if member with permission
  const canClearHistory = isOwner || (currentGroupData && currentGroupData.allowMemberClear);
  $('common-actions').hidden = !canClearHistory;
  if (isOwner && currentGroupData) {
    $('allow-member-clear-toggle').checked = !!currentGroupData.allowMemberClear;
  }

  // Key state
  updateKeyState();

  // Socket room
  if (socket) socket.emit('join_room', groupId);

  // Load messages
  await loadMessages(groupId);
  await loadMembers(groupId);

  // Close mobile sidebar
  if (window.innerWidth <= 768) closeSidebar();
}

function updateKeyState() {
  const key = currentGroupId ? getGroupKey(currentGroupId) : null;
  const hasKey = !!key;
  const input = $('message-input');
  const sendBtn = $('send-btn');
  input.disabled = !hasKey;
  input.placeholder = hasKey ? 'Type a message…' : 'Enter group key to continue';
  sendBtn.disabled = !hasKey;
}

// ── Load messages ─────────────────────────────────────────────────────────────
async function loadMessages(groupId, before) {
  // Guard: prevent the scroll handler from triggering loadOlderMessages while
  // the initial (non-paginated) load is still in flight (#2).
  if (!before) loadingOlder = true;
  try {
    const url = `/api/groups/${groupId}/messages` + (before ? `?before=${before}&limit=50` : '?limit=50');
    const res = await fetch(url);
    if (!res.ok) {
      if (res.status === 401) { window.location.href = 'index.html'; return; }
      return;
    }
    const msgs = await res.json();
    if (!before) {
      $('messages-area').innerHTML = '<div class="load-more-indicator" id="load-more-indicator" hidden>Loading older messages…</div>';
      allMessages = msgs;

      // Build all rows concurrently then insert via a single DocumentFragment
      // to avoid per-row reflows during the initial load (#26).
      const rows = await Promise.all(msgs.map(m => buildMessageRow(m)));
      const fragment = document.createDocumentFragment();
      for (const row of rows) { if (row) fragment.appendChild(row); }
      messagesArea().appendChild(fragment);
      scrollToBottom(true);
    } else {
      // Prepend older messages
      const area = messagesArea();
      const prevScrollHeight = area.scrollHeight;
      const oldFirst = area.querySelector('.msg-row, .msg-system');
      for (let i = msgs.length - 1; i >= 0; i--) {
        const row = await buildMessageRow(msgs[i]);
        if (oldFirst) area.insertBefore(row, oldFirst);
        else area.appendChild(row);
      }
      allMessages = [...msgs, ...allMessages];
      // Restore scroll position
      area.scrollTop = area.scrollHeight - prevScrollHeight;
    }
    if (msgs.length > 0) {
      oldestMessageId = msgs[0].id;
    }
  } catch(err) { console.error('loadMessages error:', err); }
  finally { if (!before) loadingOlder = false; }
}

// ── Load members ──────────────────────────────────────────────────────────────
async function loadMembers(groupId) {
  try {
    const res = await fetch(`/api/groups/${groupId}/members`);
    if (!res.ok) return;
    members = await res.json();
    $('chat-member-count').textContent = members.length + ' member' + (members.length !== 1 ? 's' : '');
    renderMembersList();
    renderWhisperPicker();
  } catch(err) { console.error('loadMembers error:', err); }
}

function renderMembersList() {
  const list = $('members-list');
  list.innerHTML = '';
  for (const m of members) {
    const li = document.createElement('li');
    li.className = 'member-item';
    li.dataset.userId = m.id;

    const av = document.createElement('div');
    av.className = 'member-avatar';
    if (m.profilePicture) {
      av.style.background = 'none';
      const img = document.createElement('img');
      img.src = m.profilePicture;
      img.style.width = '100%'; img.style.height = '100%'; img.style.objectFit = 'cover'; img.style.borderRadius = '50%';
      av.appendChild(img);
    } else {
      av.style.background = m.iconColor;
      av.textContent = m.username[0].toUpperCase();
    }

    if (onlineUsers.has(m.id)) {
      const dot = document.createElement('span');
      dot.className = 'member-online-dot';
      av.appendChild(dot);
    }

    const name = document.createElement('span');
    name.className = 'member-name';
    name.textContent = m.username;

    li.append(av, name);

    if (currentGroupData && m.id === currentGroupData.createdBy) {
      const tag = document.createElement('span');
      tag.className = 'member-owner-tag';
      tag.textContent = 'Owner';
      li.appendChild(tag);
    }

    if (currentGroupData && currentGroupData.createdBy === currentUser.id && m.id !== currentUser.id) {
      const kickBtn = document.createElement('button');
      kickBtn.className = 'member-kick-btn';
      kickBtn.title = 'Kick member';
      kickBtn.textContent = '✕';
      kickBtn.addEventListener('click', (e) => { e.stopPropagation(); kickMember(m.id, m.username); });
      li.appendChild(kickBtn);
    }

    list.appendChild(li);
  }
}

function renderWhisperPicker() {
  const list = $('whisper-picker-list');
  list.innerHTML = '';
  for (const m of members) {
    if (m.id === currentUser.id) continue;
    const item = document.createElement('div');
    item.className = 'whisper-picker-item';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.id = 'wp-' + m.id;
    cb.value = m.id;
    cb.checked = whisperRecipients.includes(m.id);
    cb.addEventListener('change', () => {
      if (cb.checked) { if (!whisperRecipients.includes(m.id)) whisperRecipients.push(m.id); }
      else whisperRecipients = whisperRecipients.filter(id => id !== m.id);
    });
    const lbl = document.createElement('label');
    lbl.htmlFor = 'wp-' + m.id;
    lbl.textContent = m.username;
    item.append(cb, lbl);
    list.appendChild(item);
  }
}

// ── Build & append message bubbles ────────────────────────────────────────────
async function buildMessageRow(msg) {
  const isOwn = msg.senderId === currentUser.id;

  // System message
  if (msg.type === 'system') {
    const div = document.createElement('div');
    div.className = 'msg-system';
    div.textContent = msg.encryptedContent;
    return div;
  }

  // Whisper — hide if not recipient or sender
  if (msg.type === 'whisper') {
    let recipients = [];
    if (msg.whisperTo) {
      try { recipients = JSON.parse(msg.whisperTo); } catch { recipients = msg.whisperTo.split(','); }
    }
    if (!isOwn && !recipients.includes(currentUser.id)) return document.createTextNode('');
  }

  const row = document.createElement('div');
  row.className = 'msg-row' + (isOwn ? ' own' : '') + (msg.type === 'whisper' ? ' whisper' : '');
  row.dataset.msgId = msg.id;
  row.dataset.senderId = msg.senderId;

  // Avatar
  const av = document.createElement('div');
  av.className = 'msg-avatar';
  // Look up profile picture from members list
  const member = members.find(m => m.id === msg.senderId);
  if (member && member.profilePicture) {
    av.style.background = 'none';
    const img = document.createElement('img');
    img.src = member.profilePicture;
    img.style.width = '100%'; img.style.height = '100%'; img.style.objectFit = 'cover'; img.style.borderRadius = '50%';
    av.appendChild(img);
  } else {
    av.style.background = msg.senderColor || '#4A90D9';
    av.textContent = (msg.senderName || '?')[0].toUpperCase();
  }

  const content = document.createElement('div');
  content.className = 'msg-content';

  // Sender name (for others)
  if (!isOwn) {
    const nameEl = document.createElement('div');
    nameEl.className = 'msg-sender-name';
    nameEl.textContent = msg.senderName || 'Unknown';
    content.appendChild(nameEl);
  }

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';
  bubble.dataset.encContent = msg.encryptedContent || '';
  bubble.dataset.iv = msg.iv || '';

  // Whisper label
  if (msg.type === 'whisper') {
    const wl = document.createElement('span');
    wl.className = 'whisper-label';
    wl.textContent = '🤫 Whisper' + (msg.whisperTo ? ' (private)' : '');
    bubble.appendChild(wl);
  }

  // Reply quote
  if (msg.replyTo) {
    try {
      const rData = typeof msg.replyTo === 'string' ? JSON.parse(msg.replyTo) : msg.replyTo;
      const rb = document.createElement('div');
      rb.className = 'msg-reply-box';
      rb.innerHTML = '<span class="msg-reply-sender">' + escapeHtml(rData.senderName || '') + '</span>' + escapeHtml(truncate(rData.preview || '', 60));
      rb.addEventListener('click', () => scrollToMessage(rData.id));
      bubble.appendChild(rb);
    } catch { /* malformed reply data */ }
  }

  // Message content
  const textEl = document.createElement('span');
  textEl.className = 'msg-text';
  await renderMsgContent(msg, textEl, bubble);

  bubble.appendChild(textEl);

  // Timestamp + delivery + edited badge
  const meta = document.createElement('span');
  meta.className = 'msg-meta';
  meta.textContent = formatTime(msg.createdAt);
  if (msg.editedAt) {
    const editedBadge = document.createElement('span');
    editedBadge.className = 'msg-edited-badge';
    editedBadge.textContent = ' (edited)';
    meta.appendChild(editedBadge);
  }
  if (isOwn) {
    const del = document.createElement('span');
    del.className = 'msg-delivery';
    del.id = 'del-' + msg.id;
    del.textContent = '✓';
    meta.appendChild(del);
  }
  bubble.appendChild(meta);

  content.appendChild(bubble);

  // Right-click context menu
  bubble.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    showContextMenu(e, msg, textEl.textContent);
  });

  // Long-press for mobile
  let longPressTimer;
  bubble.addEventListener('touchstart', () => {
    longPressTimer = setTimeout(() => showContextMenu(null, msg, textEl.textContent), 600);
  });
  bubble.addEventListener('touchend', () => clearTimeout(longPressTimer));

  if (isOwn) {
    row.append(content, av);
  } else {
    row.append(av, content);
  }

  return row;
}

async function renderMsgContent(msg, textEl, bubble) {
  const key = currentGroupId ? getGroupKey(currentGroupId) : null;

  if (!encryptionVisible) {
    if (msg.type === 'image') textEl.textContent = '[encrypted image]';
    else if (msg.type === 'file') textEl.textContent = '[encrypted file: ' + (msg.filename || '') + ']';
    else textEl.textContent = msg.encryptedContent || '[no content]';
    return;
  }

  if (msg.type === 'image') {
    if (!key) {
      const locked = document.createElement('div');
      locked.className = 'msg-image-locked';
      locked.textContent = '🔒';
      bubble.appendChild(locked);
    } else {
      const buf = await decryptBytes(msg.encryptedContent, msg.iv, key, currentGroupId);
      if (buf) {
        const mimeType = detectImageMime(buf) || 'image/jpeg';
        const blob = new Blob([buf], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img');
        img.className = 'msg-image';
        img.src = url;
        img.alt = 'image';
        img.style.cursor = 'pointer';
        img.addEventListener('click', (e) => {
          e.stopPropagation();
          showImageViewer(url);
        });
        bubble.appendChild(img);
      } else {
        const locked = document.createElement('div');
        locked.className = 'msg-image-locked';
        locked.textContent = '🔒';
        bubble.appendChild(locked);
      }
    }
    return;
  }

  if (msg.type === 'file') {
    if (!key) {
      textEl.textContent = '🔒 ' + (msg.filename || 'file');
    } else {
      const buf = await decryptBytes(msg.encryptedContent, msg.iv, key, currentGroupId);
      if (buf) {
        const btn = document.createElement('a');
        btn.className = 'msg-file-btn';
        btn.innerHTML = '<span class="msg-file-icon">📎</span>';
        const info = document.createElement('span');
        info.textContent = msg.filename || 'file';
        btn.appendChild(info);
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          const blob = new Blob([buf]);
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url; a.download = msg.filename || 'download';
          a.click(); URL.revokeObjectURL(url);
        });
        bubble.appendChild(btn);
      } else {
        textEl.textContent = '🔒 ' + (msg.filename || 'file');
      }
    }
    return;
  }

  // Text message
  if (!key) {
    textEl.textContent = MSG_NO_KEY;
    return;
  }

  const plaintext = await decryptMessage(msg.encryptedContent, msg.iv, key, currentGroupId);
  if (plaintext === null) {
    textEl.textContent = MSG_DECRYPT_FAIL;
  } else {
    textEl.textContent = plaintext;
  }
}

async function appendMessageBubble(msg, scroll) {
  const row = await buildMessageRow(msg);
  if (!row) return;

  // Grouping: hide avatar/name for consecutive messages from same sender
  const area = messagesArea();
  const rows = area.querySelectorAll('.msg-row[data-sender-id]');
  if (rows.length > 0) {
    const prev = rows[rows.length - 1];
    if (prev.dataset.senderId === msg.senderId) {
      row.classList.add('grouped');
    }
  }

  area.appendChild(row);

  // Scroll behavior
  if (scroll !== false) {
    const isAtBottom = area.scrollHeight - area.scrollTop - area.clientHeight < 150;
    if (isAtBottom) {
      scrollToBottom();
    } else {
      // User is scrolled up — increment badge
      scrollUnreadCount++;
      updateScrollBadge();
      if (msg.senderId !== currentUser.id) playNotifSound();
      row.classList.add('unread');
    }
  }
}

function updateScrollBadge() {
  const btn = $('scroll-bottom-btn');
  const badge = $('scroll-unread-badge');
  btn.hidden = false;
  badge.textContent = scrollUnreadCount;
  badge.hidden = scrollUnreadCount === 0;
}

function scrollToBottom(instant) {
  const area = messagesArea();
  if (!area) return;
  area.scrollTo({ top: area.scrollHeight, behavior: instant ? 'instant' : 'smooth' });
  scrollUnreadCount = 0;
  updateScrollBadge();
  $('scroll-bottom-btn').hidden = true;
}

function scrollToMessage(msgId) {
  const row = document.querySelector('[data-msg-id="' + msgId + '"]');
  if (row) row.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// ── Context menu ──────────────────────────────────────────────────────────────
let ctxMsg = null;
let ctxText = '';
function showContextMenu(e, msg, text) {
  ctxMsg = msg; ctxText = text;
  const menu = $('ctx-menu');
  // Show "Edit" only for own text/whisper messages
  const canEdit = msg.senderId === currentUser.id &&
    (msg.type === 'text' || msg.type === 'whisper');
  $('ctx-edit').hidden = !canEdit;
  menu.hidden = false;
  if (e) {
    menu.style.left = Math.min(e.clientX, window.innerWidth - 160) + 'px';
    menu.style.top = Math.min(e.clientY, window.innerHeight - 100) + 'px';
  } else {
    menu.style.left = '50%'; menu.style.top = '50%';
  }
}

function hideContextMenu() { $('ctx-menu').hidden = true; ctxMsg = null; }

// ── Edit message ──────────────────────────────────────────────────────────────
async function startEditMessage(msg, currentPlaintext) {
  const row = document.querySelector('[data-msg-id="' + msg.id + '"]');
  if (!row) return;
  const bubble = row.querySelector('.msg-bubble');
  const textEl = row.querySelector('.msg-text');
  if (!bubble || !textEl) return;

  // Replace text span with an inline edit form
  const editForm = document.createElement('div');
  editForm.className = 'msg-edit-form';
  const editInput = document.createElement('textarea');
  editInput.className = 'msg-edit-input';
  editInput.value = currentPlaintext;
  editInput.rows = Math.max(1, Math.ceil(currentPlaintext.length / 50));
  const editSave = document.createElement('button');
  editSave.className = 'msg-edit-save';
  editSave.textContent = 'Save';
  const editCancel = document.createElement('button');
  editCancel.className = 'msg-edit-cancel';
  editCancel.textContent = 'Cancel';
  editForm.append(editInput, editSave, editCancel);

  // Hide the text span, inject form
  textEl.hidden = true;
  bubble.insertBefore(editForm, textEl);
  editInput.focus();
  editInput.setSelectionRange(editInput.value.length, editInput.value.length);

  const cancelEdit = () => {
    editForm.remove();
    textEl.hidden = false;
  };

  editCancel.addEventListener('click', cancelEdit);
  editInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') cancelEdit();
  });

  editSave.addEventListener('click', async () => {
    const newText = editInput.value.trim();
    if (!newText || newText === currentPlaintext) { cancelEdit(); return; }
    const key = getGroupKey(currentGroupId);
    if (!key) { showToast('Set group key first', 'error'); cancelEdit(); return; }
    editSave.disabled = true;
    try {
      const { encryptedContent, iv } = await encryptMessage(newText, key, currentGroupId);
      const res = await fetch(`/api/groups/${currentGroupId}/messages/${msg.id}`, {
        method: 'PATCH',
        headers: apiHeaders(),
        body: JSON.stringify({ encryptedContent, iv }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        showToast(d.error || 'Edit failed', 'error');
        editSave.disabled = false;
      } else {
        cancelEdit();
        // The message_edited socket event will update the bubble for everyone
      }
    } catch(err) {
      console.error('Edit error:', err);
      showToast('Edit failed', 'error');
      editSave.disabled = false;
    }
  });
}

// ── Send message ──────────────────────────────────────────────────────────────
async function doSend(text) {
  if (!currentGroupId || !socket) return;
  const key = getGroupKey(currentGroupId);
  if (!key) return;
  if (!text.trim()) return;

  // Client-side rate limiting
  const now = Date.now();
  clientRateLimiter.times = clientRateLimiter.times.filter(t => now - t < 3000);
  if (clientRateLimiter.times.length >= 5) {
    showToast('⚠️ Sending too fast, slow down', 'error');
    return;
  }
  // Repeated message check
  if (text === clientRateLimiter.lastContent) {
    clientRateLimiter.repeatCount = (clientRateLimiter.repeatCount || 0) + 1;
    if (clientRateLimiter.repeatCount >= 3) {
      showToast("⚠️ Don't send the same message repeatedly", 'error');
      return;
    }
  } else {
    clientRateLimiter.repeatCount = 0;
    clientRateLimiter.lastContent = text;
  }
  clientRateLimiter.times.push(now);

  try {
    const { encryptedContent, iv } = await encryptMessage(text, key, currentGroupId);

    // Build replyTo data
    let replyToData = null;
    if (replyingTo) {
      replyToData = JSON.stringify({
        id: replyingTo.id,
        senderName: replyingTo.senderName,
        preview: replyingTo.preview,
      });
    }

    if (messageMode === 'whisper' && whisperRecipients.length > 0) {
      socket.emit('send_whisper', {
        groupId: currentGroupId,
        encryptedContent, iv,
        whisperTo: whisperRecipients,
        replyTo: replyToData,
      });
    } else {
      socket.emit('send_message', { groupId: currentGroupId, encryptedContent, iv, replyTo: replyToData });
    }

    // Stop typing indicator
    clearTimeout(window._myTypingTimer);
    socket.emit('stop_typing', { groupId: currentGroupId });

    // Clear reply
    replyingTo = null;
    $('reply-preview-bar').hidden = true;

    // Clear input
    const inp = $('message-input');
    inp.value = '';
    autoResizeTextarea(inp);
  } catch(err) {
    console.error('Encryption failed:', err);
    showToast('Failed to send message', 'error');
  }
}

// ── Toast notification ────────────────────────────────────────────────────────
function showToast(msg, type = 'info') {
  // Stack toasts: offset each new one above the previous
  const existing = document.querySelectorAll('.toast');
  const offset = existing.length * 52;
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  el.style.bottom = (24 + offset) + 'px';
  document.body.appendChild(el);
  const remove = () => {
    el.classList.add('hiding');
    setTimeout(() => el.remove(), 320);
  };
  setTimeout(remove, 3000);
}

// ── File / Image upload ───────────────────────────────────────────────────────
async function handleFileUpload(file) {
  if (!currentGroupId || !socket) return;
  const key = getGroupKey(currentGroupId);
  if (!key) { showToast('Set group key first', 'error'); return; }

  const MAX_RAW = 25 * 1024 * 1024 * 1024; // 25GB

  let processedFile = file;
  const isImage = file.type.startsWith('image/');

  if (isImage) {
    processedFile = await compressImage(file);
    if (processedFile.size > MAX_RAW) {
      showToast('Image too large (max 25GB after compression)', 'error');
      return;
    }
  } else {
    if (file.size > MAX_RAW) {
      showToast('File too large (max 25GB)', 'error');
      return;
    }
  }

  try {
    const buffer = await processedFile.arrayBuffer();
    const { encryptedContent, iv } = await encryptBytes(buffer, key, currentGroupId);

    const body = { encryptedContent, iv, type: isImage ? 'image' : 'file', filename: file.name };
    const res = await fetch(`/api/groups/${currentGroupId}/upload`, {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      showToast(d.error || 'Upload failed', 'error');
    }
  } catch(err) {
    console.error('File upload error:', err);
    showToast('Upload failed', 'error');
  }
}

// ── Socket.IO ─────────────────────────────────────────────────────────────────
function initSocket() {
  socket = io({ transports: ['polling', 'websocket'] });

  socket.on('connect', () => {
    $('conn-dot').className = 'conn-dot connected';
    $('conn-label').textContent = 'Connected';
    $('reconnect-banner').hidden = true;
    if (currentGroupId) socket.emit('join_room', currentGroupId);
  });

  socket.on('disconnect', () => {
    $('conn-dot').className = 'conn-dot';
    $('conn-label').textContent = 'Disconnected';
    $('reconnect-banner').hidden = false;
  });

  socket.on('connect_error', () => {
    $('conn-dot').className = 'conn-dot';
    $('conn-label').textContent = 'Connection error';
  });

  socket.on('new_message', async (msg) => {
    // Increment page title notification if document is not focused
    if (!document.hasFocus() && msg.senderId !== currentUser.id) {
      unreadNotificationCount++;
      updatePageTitleNotification();
    }

    if (msg.groupId !== currentGroupId) {
      // Increment unread for non-active group
      unreadCounts[msg.groupId] = (unreadCounts[msg.groupId] || 0) + 1;
      updateUnreadBadge(msg.groupId, unreadCounts[msg.groupId]);
      playNotifSound();
      // Update last message preview
      const key = getGroupKey(msg.groupId);
      let preview = '[encrypted]';
      if (key && msg.type === 'text') {
        const pt = await decryptMessage(msg.encryptedContent, msg.iv, key, msg.groupId);
        if (pt) preview = pt;
      } else if (msg.type === 'image') preview = '[Image]';
      else if (msg.type === 'file') preview = '[File: ' + (msg.filename || '') + ']';
      else if (msg.type === 'whisper') preview = '[Whisper]';
      updateGroupPreview(msg.groupId, preview, msg.createdAt);
      return;
    }
    await appendMessageBubble(msg, true);
    // Update preview
    const key2 = getGroupKey(msg.groupId);
    let preview2 = '[encrypted]';
    if (key2 && msg.type === 'text') {
      const pt2 = await decryptMessage(msg.encryptedContent, msg.iv, key2, msg.groupId);
      if (pt2) preview2 = pt2;
    } else if (msg.type === 'image') preview2 = '[Image]';
    else if (msg.type === 'file') preview2 = '[File: ' + (msg.filename || '') + ']';
    else if (msg.type === 'whisper') preview2 = '[Whisper]';
    updateGroupPreview(msg.groupId, preview2, msg.createdAt);
  });

  socket.on('message_delivered', ({ messageId }) => {
    const del = $('del-' + messageId);
    if (del) { del.textContent = '✓✓'; del.classList.add('delivered'); }
  });

  socket.on('message_deleted', ({ messageId }) => {
    const row = document.querySelector('[data-msg-id="' + messageId + '"]');
    if (row) row.remove();
  });

  socket.on('message_edited', async ({ messageId, encryptedContent, iv, editedAt }) => {
    const row = document.querySelector('[data-msg-id="' + messageId + '"]');
    if (!row) return;
    const bubble = row.querySelector('.msg-bubble');
    const textEl = row.querySelector('.msg-text');
    if (!bubble || !textEl) return;

    // Update the stored ciphertext on the bubble dataset
    bubble.dataset.encContent = encryptedContent;
    bubble.dataset.iv = iv;

    // Re-decrypt and update display text
    const key = currentGroupId ? getGroupKey(currentGroupId) : null;
    if (key) {
      const pt = await decryptMessage(encryptedContent, iv, key, currentGroupId);
      textEl.textContent = pt !== null ? pt : MSG_DECRYPT_FAIL;
    } else {
      textEl.textContent = MSG_NO_KEY;
    }

    // Add or update the "(edited)" badge in the meta line
    const metaEl = bubble.querySelector('.msg-meta');
    if (metaEl && !metaEl.querySelector('.msg-edited-badge')) {
      const badge = document.createElement('span');
      badge.className = 'msg-edited-badge';
      badge.textContent = ' (edited)';
      // Insert before delivery receipt if present
      const delEl = metaEl.querySelector('.msg-delivery');
      if (delEl) metaEl.insertBefore(badge, delEl);
      else metaEl.appendChild(badge);
    }

    // Keep allMessages in sync
    const stored = allMessages.find(m => m.id === messageId);
    if (stored) { stored.encryptedContent = encryptedContent; stored.iv = iv; stored.editedAt = editedAt; }
  });

  socket.on('chat_cleared', ({ groupId }) => {
    if (groupId !== currentGroupId) return;
    const area = messagesArea();
    area.innerHTML = '<div class="load-more-indicator" id="load-more-indicator" hidden>Loading older messages…</div>';
    allMessages = [];
    addSystemMessage('Chat history was cleared');
  });

  socket.on('group_renamed', ({ groupId, newName }) => {
    const g = groups.find(x => x.id === groupId);
    if (g) g.name = newName;
    if (groupId === currentGroupId) {
      $('chat-group-name').textContent = newName;
      $('right-group-name').textContent = newName;
    }
    renderGroupList();
  });

  socket.on('member_joined', ({ userId, username, iconColor, groupId }) => {
    if (groupId !== currentGroupId) return;
    addSystemMessage('👋 ' + username + ' joined the group');
    if (!members.find(m => m.id === userId)) {
      members.push({ id: userId, username, iconColor });
      renderMembersList();
      renderWhisperPicker();
      $('chat-member-count').textContent = members.length + ' member' + (members.length !== 1 ? 's' : '');
    }
  });

  socket.on('member_left', ({ userId, username, groupId }) => {
    if (groupId !== currentGroupId) return;
    addSystemMessage('👋 ' + username + ' left the group');
    members = members.filter(m => m.id !== userId);
    renderMembersList();
    renderWhisperPicker();
    $('chat-member-count').textContent = members.length + ' member' + (members.length !== 1 ? 's' : '');
  });

  socket.on('member_kicked', ({ userId, groupId }) => {
    if (userId === currentUser.id) {
      // We were kicked
      groups = groups.filter(g => g.id !== groupId);
      renderGroupList();
      if (groupId === currentGroupId) {
        currentGroupId = null; currentGroupData = null;
        $('chat-active').hidden = true;
        $('chat-empty').hidden = false;
      }
      return;
    }
    if (groupId !== currentGroupId) return;
    const m = members.find(x => x.id === userId);
    if (m) addSystemMessage('🚫 ' + m.username + ' was removed from the group');
    members = members.filter(x => x.id !== userId);
    renderMembersList();
    renderWhisperPicker();
  });

  socket.on('group_disbanded', ({ groupId }) => {
    groups = groups.filter(g => g.id !== groupId);
    renderGroupList();
    if (groupId === currentGroupId) {
      currentGroupId = null; currentGroupData = null;
      members = [];
      $('chat-active').hidden = true;
      $('chat-empty').hidden = false;
      $('right-panel-content').hidden = true;
      $('right-panel-empty').hidden = false;
      addSystemMessage('This group has been disbanded');
    }
  });

  socket.on('presence_update', ({ groupId, onlineUserIds }) => {
    if (groupId !== currentGroupId) return;
    onlineUsers = new Set(onlineUserIds);
    renderMembersList();
  });

  socket.on('user_updated', (user) => {
    // Update member display names if affected
    const m = members.find(x => x.id === user.id);
    if (m) {
      m.username = user.username;
      m.iconColor = user.iconColor;
      renderMembersList();
    }
    if (user.id === currentUser.id) {
      currentUser = user;
      $('user-username').textContent = user.username;
      $('user-avatar').textContent = user.username[0].toUpperCase();
      $('user-avatar').style.background = user.iconColor;
    }
    // Update avatars and sender names in visible message bubbles
    document.querySelectorAll('.msg-row[data-sender-id="' + CSS.escape(String(user.id)) + '"]').forEach(row => {
      const av = row.querySelector('.msg-avatar');
      if (av && user.username) { av.style.background = user.iconColor; av.textContent = user.username[0].toUpperCase(); }
      const nameEl = row.querySelector('.msg-sender-name');
      if (nameEl && user.username) nameEl.textContent = user.username;
    });
  });

  socket.on('user_typing', ({ username }) => {
    $('typing-user').textContent = username;
    $('typing-indicator').hidden = false;
    clearTimeout(window._typingTimer);
    window._typingTimer = setTimeout(() => $('typing-indicator').hidden = true, 3000);
  });

  socket.on('user_stop_typing', () => {
    $('typing-indicator').hidden = true;
  });

  socket.on('error', ({ message }) => {
    showToast(message || 'An error occurred', 'error');
  });
}

function addSystemMessage(text) {
  const div = document.createElement('div');
  div.className = 'msg-system';
  div.textContent = text;
  messagesArea().appendChild(div);
  scrollToBottom();
}

// ── Emoji picker ──────────────────────────────────────────────────────────────
function setupEmojiPicker() {
  const emojis = ['😀','😂','🥰','😍','😎','🤩','🥳','😭','😤','🤔','😏','😇','🙄','😴','🤗','🥺','😱','😜','🤪','😝','🤑','😈','👹','💀','💩','��','👻','👾','🙈','🐶','🐱','🐭','🐰','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐙','🦋','🌺','🌸','🍎','🍕','🎂','🎉','🎊','🎁','❤️','🧡','💛','💚','💙','💜','🖤','💔','✨','⭐','🌟','🔥','💫','🌈','☀️','🌙','❄️','🎵','🎶','🏆','👑','💎','🗝️','🔑','🌍','🚀','🎭','👋','🤝','👍','👎','🙏','💪','✌️','🤞','🤟','👆','👇','👈','👉'];
  const picker = $('emoji-picker');
  for (const em of emojis) {
    const btn = document.createElement('button');
    btn.className = 'emoji-btn-item';
    btn.textContent = em;
    btn.addEventListener('click', () => insertEmoji(em));
    picker.appendChild(btn);
  }
}

function insertEmoji(em) {
  const inp = $('message-input');
  const start = inp.selectionStart;
  const end = inp.selectionEnd;
  inp.value = inp.value.slice(0, start) + em + inp.value.slice(end);
  inp.selectionStart = inp.selectionEnd = start + em.length;
  inp.focus();
  autoResizeTextarea(inp);
  $('emoji-picker').hidden = true;
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
function setupKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      // Close modals
      document.querySelectorAll('.modal-overlay:not([hidden])').forEach(m => m.hidden = true);
      $('ctx-menu').hidden = true;
      $('emoji-picker').hidden = true;
      $('whisper-picker').hidden = true;
      // Close image viewer
      hideImageViewer();
      // Cancel reply
      replyingTo = null;
      $('reply-preview-bar').hidden = true;
    }
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && document.activeElement !== $('message-input')) {
      $('shortcuts-modal').hidden = false;
    }
  });
}

// ── Auto-resize textarea ──────────────────────────────────────────────────────
function autoResizeTextarea(el) {
  el.style.height = 'auto';
  const maxH = 5 * 20 + 18; // ~5 lines
  el.style.height = Math.min(el.scrollHeight, maxH) + 'px';
}

// ── Whisper mode ──────────────────────────────────────────────────────────────
function updateWhisperBtn() {
  const btn = $('whisper-mode-btn');
  if (messageMode === 'whisper') {
    btn.textContent = '🤫';
    btn.classList.add('whisper-active');
    $('whisper-picker').hidden = false;
  } else {
    btn.textContent = '📢';
    btn.classList.remove('whisper-active');
    $('whisper-picker').hidden = true;
  }
}

// ── Toggle encryption display ─────────────────────────────────────────────────
async function toggleEncryption() {
  encryptionVisible = !encryptionVisible;
  $('enc-toggle-btn').textContent = encryptionVisible ? '🔒 Hide Encryption' : '🔓 Show Encrypted';
  // Re-render all messages
  if (!currentGroupId) return;
  await loadMessages(currentGroupId);
}

// ── Forget key ────────────────────────────────────────────────────────────────
function forgetKey() {
  showConfirm(
    'Forget Encryption Key',
    'This will remove your encryption key for this group. You won\'t be able to read or send messages until you re-enter it. Continue?',
    async () => {
      clearGroupKey(currentGroupId);
      updateKeyState();
      await loadMessages(currentGroupId);
      showToast('🗝 Key forgotten — messages are now locked', 'info');
    }
  );
}

// ── Kick member ───────────────────────────────────────────────────────────────
async function kickMember(userId, username) {
  showConfirm('Kick Member', 'Remove ' + username + ' from this group?', async () => {
    const res = await fetch('/api/groups/' + currentGroupId + '/members/' + userId, {
      method: 'DELETE', headers: apiHeaders(),
    });
    if (res.ok) {
      showToast('Kicked ' + username, 'success');
    } else {
      const d = await res.json().catch(() => ({}));
      showToast(d.error || 'Failed to kick member', 'error');
    }
  });
}

// ── Generic confirm modal ─────────────────────────────────────────────────────
let confirmCallback = null;
function showConfirm(title, message, onConfirm) {
  $('confirm-title').textContent = title;
  $('confirm-message').textContent = message;
  $('confirm-modal').hidden = false;
  confirmCallback = onConfirm;
}

// ── Search messages ───────────────────────────────────────────────────────────
function highlightText(el, term) {
  // DOM-based highlighting — no innerHTML with user content
  el.textContent = el.textContent; // reset to plain text
  if (!term) return;
  const text = el.textContent;
  const lc = text.toLowerCase();
  const tl = term.toLowerCase();
  el.textContent = '';
  let idx = 0;
  let found;
  while ((found = lc.indexOf(tl, idx)) !== -1) {
    if (found > idx) el.appendChild(document.createTextNode(text.slice(idx, found)));
    const mark = document.createElement('mark');
    mark.className = 'search-highlight';
    mark.textContent = text.slice(found, found + term.length);
    el.appendChild(mark);
    idx = found + term.length;
  }
  if (idx < text.length) el.appendChild(document.createTextNode(text.slice(idx)));
}

function searchMessages(term) {
  const rows = messagesArea().querySelectorAll('.msg-row');
  let count = 0;
  rows.forEach(row => {
    const textEl = row.querySelector('.msg-text');
    if (!textEl) return;
    // Restore plain text first (remove marks)
    textEl.textContent = textEl.textContent;
    if (!term) { row.style.display = ''; return; }
    const text = textEl.textContent;
    if (text.toLowerCase().includes(term.toLowerCase())) {
      count++;
      row.style.display = '';
      highlightText(textEl, term);
    } else {
      row.style.display = 'none';
    }
  });
  $('search-results-count').textContent = term ? count + ' result' + (count !== 1 ? 's' : '') : '';
}

// ── Export chat ───────────────────────────────────────────────────────────────
async function exportChat() {
  const key = getGroupKey(currentGroupId);
  const lines = [];
  for (const msg of allMessages) {
    const time = formatTime(msg.createdAt);
    let content = '';
    if (msg.type === 'image') content = '[Image]';
    else if (msg.type === 'file') content = '[File: ' + (msg.filename || '') + ']';
    else if (key) {
      const pt = await decryptMessage(msg.encryptedContent, msg.iv, key, currentGroupId);
      content = pt || MSG_DECRYPT_FAIL;
    } else {
      content = MSG_NO_KEY;
    }
    lines.push('[' + time + '] ' + (msg.senderName || 'Unknown') + ': ' + content);
  }
  if (!lines.length) { showToast('No messages to export', 'info'); return; }
  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const date = new Date().toISOString().slice(0, 10);
  const gname = (currentGroupData ? currentGroupData.name : 'chat').replace(/[^a-zA-Z0-9]/g, '-');
  a.href = url; a.download = 'gaychat-' + gname + '-' + date + '.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Event listeners ───────────────────────────────────────────────────────────
function setupEventListeners() {
  // Logout
  $('logout-btn').addEventListener('click', async (e) => {
    e.stopPropagation();
    await fetch('/api/auth/logout', { method: 'POST', headers: apiHeaders() });
    window.location.href = 'index.html';
  });

  // Profile modal
  $('sidebar-user-btn').addEventListener('click', () => {
    $('profile-username').value = currentUser.username;
    $('profile-color').value = currentUser.iconColor;
    $('profile-error').textContent = '';
    $('profile-modal').hidden = false;
  });
  $('profile-cancel-btn').addEventListener('click', () => $('profile-modal').hidden = true);

  $('profile-save-username').addEventListener('click', async () => {
    const username = $('profile-username').value.trim();
    if (!username) return;
    const res = await fetch('/api/auth/profile', {
      method: 'PATCH', headers: apiHeaders(),
      body: JSON.stringify({ username }),
    });
    const d = await res.json();
    if (!res.ok) { $('profile-error').textContent = d.error || 'Failed'; return; }
    currentUser = d;
    $('user-username').textContent = d.username;
    $('user-avatar').textContent = d.username[0].toUpperCase();
    $('profile-error').textContent = '✓ Saved';
  });

  $('profile-save-color').addEventListener('click', async () => {
    const iconColor = $('profile-color').value;
    const res = await fetch('/api/auth/profile', {
      method: 'PATCH', headers: apiHeaders(),
      body: JSON.stringify({ iconColor }),
    });
    const d = await res.json();
    if (!res.ok) { $('profile-error').textContent = d.error || 'Failed'; return; }
    currentUser = d;
    const ua = $('user-avatar');
    if (d.profilePicture) {
      ua.innerHTML = ''; ua.style.background = 'none';
      const img = document.createElement('img');
      img.src = d.profilePicture; img.style.width = '100%'; img.style.height = '100%'; img.style.objectFit = 'cover'; img.style.borderRadius = '50%';
      ua.appendChild(img);
    } else {
      ua.innerHTML = ''; ua.textContent = d.username[0].toUpperCase(); ua.style.background = d.iconColor;
    }
    $('profile-error').textContent = '✓ Saved';
  });

  // Profile picture type toggle
  document.querySelectorAll('input[name="profile-picture-type"]').forEach(radio => {
    radio.addEventListener('change', () => {
      const type = document.querySelector('input[name="profile-picture-type"]:checked').value;
      $('profile-picture-color-section').hidden = type !== 'color';
      $('profile-picture-upload-section').hidden = type !== 'image';
    });
  });

  // Profile picture upload preview
  $('profile-picture-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      $('profile-error').textContent = 'Image too large (max 2MB)';
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      $('profile-picture-preview-img').src = e.target.result;
      $('profile-picture-preview').hidden = false;
    };
    reader.readAsDataURL(file);
  });

  // Save profile picture
  $('profile-save-picture').addEventListener('click', async () => {
    const file = $('profile-picture-input').files[0];
    if (!file) { $('profile-error').textContent = 'Please select an image'; return; }
    if (file.size > 2 * 1024 * 1024) {
      $('profile-error').textContent = 'Image too large (max 2MB)';
      return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
      const profilePicture = e.target.result;
      const res = await fetch('/api/auth/profile', {
        method: 'PATCH', headers: apiHeaders(),
        body: JSON.stringify({ profilePicture }),
      });
      const d = await res.json();
      if (!res.ok) { $('profile-error').textContent = d.error || 'Failed'; return; }
      currentUser = d;
      const ua = $('user-avatar');
      ua.innerHTML = ''; ua.style.background = 'none';
      const img = document.createElement('img');
      img.src = d.profilePicture;
      img.style.width = '100%'; img.style.height = '100%'; img.style.objectFit = 'cover'; img.style.borderRadius = '50%';
      ua.appendChild(img);
      $('profile-error').textContent = '✓ Saved';
    };
    reader.readAsDataURL(file);
  });

  // Remove profile picture
  $('profile-remove-picture').addEventListener('click', async () => {
    const res = await fetch('/api/auth/profile', {
      method: 'PATCH', headers: apiHeaders(),
      body: JSON.stringify({ profilePicture: null }),
    });
    const d = await res.json();
    if (!res.ok) { $('profile-error').textContent = d.error || 'Failed'; return; }
    currentUser = d;
    const ua = $('user-avatar');
    ua.innerHTML = ''; ua.textContent = d.username[0].toUpperCase(); ua.style.background = d.iconColor;
    $('profile-picture-preview').hidden = true;
    $('profile-picture-input').value = '';
    $('profile-error').textContent = '✓ Removed';
  });

  $('profile-delete-btn').addEventListener('click', () => {
    showConfirm('Delete Account', 'Permanently delete your account? This cannot be undone.', async () => {
      $('profile-modal').hidden = true;
      const res = await fetch('/api/auth/account', { method: 'DELETE', headers: apiHeaders() });
      if (res.ok) window.location.href = 'index.html';
    });
  });

  // Create group
  $('new-group-btn').addEventListener('click', () => {
    $('create-group-name').value = '';
    $('create-group-code').value = '';
    $('create-error').textContent = '';
    $('create-modal').hidden = false;
  });
  $('create-cancel-btn').addEventListener('click', () => $('create-modal').hidden = true);
  $('create-confirm-btn').addEventListener('click', async () => {
    const name = $('create-group-name').value.trim();
    const code = $('create-group-code').value.trim();
    $('create-error').textContent = '';
    if (!name || !code) { $('create-error').textContent = 'Both fields are required'; return; }
    const res = await fetch('/api/groups/create', {
      method: 'POST', headers: apiHeaders(),
      body: JSON.stringify({ name, code }),
    });
    const d = await res.json();
    if (!res.ok) { $('create-error').textContent = d.error || 'Failed'; return; }
    $('create-modal').hidden = true;
    groups.unshift(d);
    renderGroupList();
    await selectGroup(d.id);
    addSystemMessage('🎉 Group "' + d.name + '" created!');
  });

  // Join group
  $('join-group-btn').addEventListener('click', () => {
    $('join-group-code').value = '';
    $('join-error').textContent = '';
    $('join-modal').hidden = false;
  });
  $('join-cancel-btn').addEventListener('click', () => $('join-modal').hidden = true);
  $('join-confirm-btn').addEventListener('click', async () => {
    const code = $('join-group-code').value.trim();
    $('join-error').textContent = '';
    if (!code) { $('join-error').textContent = 'Enter a group code'; return; }
    const res = await fetch('/api/groups/join', {
      method: 'POST', headers: apiHeaders(),
      body: JSON.stringify({ code }),
    });
    const d = await res.json();
    if (!res.ok) { $('join-error').textContent = d.error || 'Failed'; return; }
    $('join-modal').hidden = true;
    if (!groups.find(g => g.id === d.id)) { groups.unshift(d); renderGroupList(); }
    await selectGroup(d.id);
    addSystemMessage('👋 You joined "' + d.name + '"!');
  });

  // Set group key
  $('set-key-btn').addEventListener('click', () => {
    $('group-key-input').value = currentGroupId ? (getGroupKey(currentGroupId) || '') : '';
    $('group-key-error').textContent = '';
    $('group-key-modal').hidden = false;
  });
  $('group-key-cancel-btn').addEventListener('click', () => $('group-key-modal').hidden = true);
  $('group-key-save-btn').addEventListener('click', async () => {
    const key = $('group-key-input').value;
    if (!key) { $('group-key-error').textContent = 'Key cannot be empty'; return; }
    setGroupKey(currentGroupId, key);
    $('group-key-modal').hidden = true;
    updateKeyState();
    await loadMessages(currentGroupId);
  });

  // Encryption toggle
  $('enc-toggle-btn').addEventListener('click', toggleEncryption);

  // Forget key
  $('forget-key-btn').addEventListener('click', forgetKey);

  // Copy code
  $('copy-code-btn').addEventListener('click', () => {
    if (!currentGroupData) return;
    navigator.clipboard.writeText(currentGroupData.code).catch(() => {});
    $('copy-code-btn').textContent = '✅';
    setTimeout(() => $('copy-code-btn').textContent = '📋', 1500);
  });

  // Edit group name
  $('edit-group-name-btn').addEventListener('click', () => {
    $('edit-group-name-input').value = currentGroupData ? currentGroupData.name : '';
    $('edit-group-name-form').hidden = false;
    $('edit-group-name-btn').hidden = true;
    $('edit-group-name-input').focus();
  });
  $('edit-group-name-cancel').addEventListener('click', () => {
    $('edit-group-name-form').hidden = true;
    $('edit-group-name-btn').hidden = false;
  });
  $('edit-group-name-save').addEventListener('click', async () => {
    const name = $('edit-group-name-input').value.trim();
    if (!name || !currentGroupId) return;
    const res = await fetch('/api/groups/' + currentGroupId + '/name', {
      method: 'PATCH', headers: apiHeaders(),
      body: JSON.stringify({ name }),
    });
    if (res.ok) {
      $('edit-group-name-form').hidden = true;
      $('edit-group-name-btn').hidden = false;
    } else {
      const d = await res.json().catch(() => ({}));
      showToast(d.error || 'Failed to rename', 'error');
    }
  });

  // Clear chat history
  $('clear-history-btn').addEventListener('click', () => {
    showConfirm(
      'Clear Chat History',
      'This will permanently delete all messages for everyone. Continue?',
      async () => {
        const res = await fetch('/api/groups/' + currentGroupId + '/messages', {
          method: 'DELETE', headers: apiHeaders(),
        });
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          showToast(d.error || 'Failed', 'error');
        }
      }
    );
  });

  // Allow member clear toggle
  $('allow-member-clear-toggle').addEventListener('change', async (e) => {
    await fetch('/api/groups/' + currentGroupId + '/settings', {
      method: 'PATCH', headers: apiHeaders(),
      body: JSON.stringify({ allowMemberClear: e.target.checked }),
    });
    if (currentGroupData) currentGroupData.allowMemberClear = e.target.checked;
  });

  // Export chat
  $('export-btn').addEventListener('click', exportChat);

  // Disband group
  $('disband-btn').addEventListener('click', () => {
    showConfirm('Disband Group', 'Permanently disband this group and delete all messages?', async () => {
      const res = await fetch('/api/groups/' + currentGroupId, {
        method: 'DELETE', headers: apiHeaders(),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        showToast(d.error || 'Failed', 'error');
      }
    });
  });

  // Leave group
  $('leave-group-btn').addEventListener('click', () => {
    showConfirm('Leave Group', 'Are you sure you want to leave this group?', async () => {
      const res = await fetch('/api/groups/' + currentGroupId + '/leave', {
        method: 'DELETE', headers: apiHeaders(),
      });
      if (res.ok) {
        groups = groups.filter(g => g.id !== currentGroupId);
        renderGroupList();
        currentGroupId = null; currentGroupData = null;
        $('chat-active').hidden = true;
        $('chat-empty').hidden = false;
        $('right-panel-content').hidden = true;
        $('right-panel-empty').hidden = false;
        showToast('🚪 Left group', 'success');
      } else {
        const d = await res.json().catch(() => ({}));
        showToast(d.error || 'Failed', 'error');
      }
    });
  });

  // Confirm modal
  $('confirm-cancel-btn').addEventListener('click', () => { $('confirm-modal').hidden = true; confirmCallback = null; });
  $('confirm-ok-btn').addEventListener('click', () => {
    $('confirm-modal').hidden = true;
    if (confirmCallback) { confirmCallback(); confirmCallback = null; }
  });

  // Shortcuts modal
  $('shortcuts-close-btn').addEventListener('click', () => $('shortcuts-modal').hidden = true);

  // Context menu actions
  $('ctx-reply').addEventListener('click', () => {
    if (!ctxMsg) return;
    const msg = ctxMsg;
    const text = ctxText;
    hideContextMenu();
    const isDecryptFail = text === MSG_NO_KEY || text === MSG_DECRYPT_FAIL;
    let preview;
    if (text && !isDecryptFail) {
      preview = text;
    } else if (msg.type === 'image') {
      preview = '[image]';
    } else if (msg.type === 'file') {
      preview = '[file: ' + (msg.filename || '') + ']';
    } else {
      preview = '[encrypted]';
    }
    replyingTo = {
      id: msg.id,
      senderName: msg.senderName,
      preview,
    };
    $('reply-preview-name').textContent = msg.senderName;
    $('reply-preview-text').textContent = truncate(replyingTo.preview, 80);
    $('reply-preview-bar').hidden = false;
    $('message-input').focus();
  });

  $('ctx-copy').addEventListener('click', () => {
    if (ctxText) navigator.clipboard.writeText(ctxText).catch(() => {});
    hideContextMenu();
  });

  $('ctx-edit').addEventListener('click', () => {
    if (!ctxMsg) return;
    const msg = ctxMsg;
    const text = ctxText;
    hideContextMenu();
    const isDecryptFail = text === MSG_NO_KEY || text === MSG_DECRYPT_FAIL;
    if (isDecryptFail) { showToast('Cannot edit — message not decrypted', 'error'); return; }
    startEditMessage(msg, text);
  });

  document.addEventListener('click', (e) => {
    if (!$('ctx-menu').contains(e.target)) hideContextMenu();
    if (!$('emoji-picker').contains(e.target) && e.target !== $('emoji-btn')) {
      $('emoji-picker').hidden = true;
    }
  });

  // Reply cancel
  $('reply-cancel-btn').addEventListener('click', () => {
    replyingTo = null;
    $('reply-preview-bar').hidden = true;
  });

  // Message input
  const msgInput = $('message-input');

  msgInput.addEventListener('input', () => {
    autoResizeTextarea(msgInput);
    if (currentGroupId && socket) {
      socket.emit('typing', { groupId: currentGroupId });
      clearTimeout(window._myTypingTimer);
      window._myTypingTimer = setTimeout(() => {
        socket.emit('stop_typing', { groupId: currentGroupId });
      }, 1500);
    }
  });

  msgInput.addEventListener('blur', () => {
    clearTimeout(window._myTypingTimer);
    if (currentGroupId && socket) socket.emit('stop_typing', { groupId: currentGroupId });
  });

  msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      doSend(msgInput.value);
    }
  });

  $('send-btn').addEventListener('click', () => doSend(msgInput.value));

  // File input
  $('file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) { handleFileUpload(file); e.target.value = ''; }
  });

  // Paste image
  msgInput.addEventListener('paste', async (e) => {
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) await handleFileUpload(file);
        return;
      }
    }
  });

  // Emoji button
  $('emoji-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    $('emoji-picker').hidden = !$('emoji-picker').hidden;
  });

  // Whisper mode toggle
  $('whisper-mode-btn').addEventListener('click', () => {
    messageMode = messageMode === 'normal' ? 'whisper' : 'normal';
    updateWhisperBtn();
  });

  // Scroll to bottom button
  $('scroll-bottom-btn').addEventListener('click', () => scrollToBottom());

  // Scroll listener for pagination + scroll-to-bottom visibility
  messagesArea().addEventListener('scroll', () => {
    const area = messagesArea();
    const isAtBottom = area.scrollHeight - area.scrollTop - area.clientHeight < 150;
    $('scroll-bottom-btn').hidden = isAtBottom;
    if (isAtBottom) {
      scrollUnreadCount = 0;
      $('scroll-unread-badge').hidden = true;
      // Clear unread marks
      area.querySelectorAll('.msg-row.unread').forEach(r => r.classList.remove('unread'));
    }
    // Infinite scroll up
    if (area.scrollTop <= SCROLL_LOAD_THRESHOLD && !loadingOlder && oldestMessageId) {
      loadOlderMessages();
    }
  });

  // Right panel toggle (mobile)
  $('right-panel-toggle').addEventListener('click', () => {
    $('right-panel').classList.toggle('open');
  });

  // Mobile empty state toggles
  $('sidebar-toggle-empty').addEventListener('click', () => {
    $('sidebar').classList.toggle('open');
    $('sidebar-overlay').hidden = !$('sidebar').classList.contains('open');
  });

  $('right-panel-toggle-empty').addEventListener('click', () => {
    $('right-panel').classList.toggle('open');
  });

  // Mobile sidebar
  $('sidebar-toggle').addEventListener('click', () => {
    $('sidebar').classList.toggle('open');
    $('sidebar-overlay').hidden = !$('sidebar').classList.contains('open');
  });
  $('sidebar-overlay').addEventListener('click', closeSidebar);

  // Search
  $('search-input').addEventListener('input', (e) => searchMessages(e.target.value));
  $('clear-search-btn').addEventListener('click', () => {
    $('search-input').value = '';
    searchMessages('');
  });

  // Unread jump button
  $('unread-jump-btn').addEventListener('click', () => {
    const first = messagesArea().querySelector('.msg-row.unread');
    if (first) first.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  // Image viewer
  $('image-viewer-close').addEventListener('click', hideImageViewer);
  $('image-viewer-overlay').addEventListener('click', hideImageViewer);
  $('image-viewer-img').addEventListener('click', hideImageViewer);
}

async function loadOlderMessages() {
  if (loadingOlder || !oldestMessageId || !currentGroupId) return;
  loadingOlder = true;
  const indicator = $('load-more-indicator');
  if (indicator) indicator.hidden = false;
  try {
    const url = `/api/groups/${currentGroupId}/messages?before=${oldestMessageId}&limit=50`;
    const res = await fetch(url);
    if (!res.ok) return;
    const msgs = await res.json();
    if (!msgs.length) {
      oldestMessageId = null; // no more older messages
      return;
    }

    const area = messagesArea();
    const prevScrollHeight = area.scrollHeight;

    // Build all rows concurrently (msgs is oldest-first from server)
    const rows = await Promise.all(msgs.map(m => buildMessageRow(m)));

    // Assemble into a fragment (single DOM mutation, no scroll drift)
    const fragment = document.createDocumentFragment();
    for (const row of rows) {
      if (row) fragment.appendChild(row);
    }

    // Single DOM mutation — prepend the whole fragment
    const oldFirst = area.querySelector('.msg-row, .msg-system');
    if (oldFirst) {
      area.insertBefore(fragment, oldFirst);
    } else {
      area.appendChild(fragment);
    }

    allMessages = [...msgs, ...allMessages];
    oldestMessageId = msgs[0].id;

    // Restore scroll position in one step
    area.scrollTop = area.scrollHeight - prevScrollHeight;
  } catch(err) {
    console.error('loadOlderMessages error:', err);
  } finally {
    loadingOlder = false;
    if (indicator) indicator.hidden = true;
  }
}

function closeSidebar() {
  $('sidebar').classList.remove('open');
  $('sidebar-overlay').hidden = true;
}
