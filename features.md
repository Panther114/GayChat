# GayChat Features

This document tracks all implemented features in the GayChat application. All features listed below are currently implemented and working.

## Authentication & User Management
- [x] User registration with username and password
- [x] User login with bcrypt password hashing (cost factor 12)
- [x] Session management with express-session and SQLite store
- [x] User profile customization (username and icon color)
- [x] Account deletion
- [x] Secure session cookies (httpOnly, sameSite, secure in production)
- [x] CSRF protection with double-submit token pattern
- [x] Admin endpoint to view registered users (with ADMIN_SECRET)

## End-to-End Encryption
- [x] AES-256-GCM client-side encryption for all messages
- [x] PBKDF2 key derivation (100,000 iterations, SHA-256)
- [x] Per-group encryption keys stored in localStorage
- [x] Encryption key setup interface
- [x] Automatic encryption/decryption of messages
- [x] Support for encrypted file and image uploads
- [x] Server stores only ciphertext and IV, never plaintext

## Group Chat Management
- [x] Create new groups with custom name and code
- [x] Join existing groups via shareable code
- [x] View list of user's groups
- [x] Group member list display
- [x] Leave group (non-owners)
- [x] Disband group (owner only)
- [x] Rename group (all members can rename)
- [x] Group ownership tracking
- [x] Configurable member permissions (allow_member_clear setting)

## Messaging Features
- [x] Real-time text messaging via Socket.IO
- [x] Message encryption/decryption
- [x] Message timestamps with timezone formatting
- [x] Reply/Quote functionality
- [x] Whisper mode (private messages to selected members)
- [x] Image sharing with auto-compression (max 1200px, 75% JPEG quality)
- [x] File sharing (1MB limit)
- [x] Image MIME type detection (JPEG, PNG, GIF, WebP)
- [x] Message deletion (sender or group owner)
- [x] Clear all messages (owner, or members if allowed)
- [x] Paginated message loading (50 messages per page, max 100)
- [x] Load older messages on scroll
- [x] Message size limit enforcement (1MB encrypted content)

## User Interface & Experience
- [x] Modern dark glassmorphism UI
- [x] Gradient message bubbles
- [x] Emoji picker (80 emojis)
- [x] Search messages with client-side highlighting
- [x] Export chat history as TXT file
- [x] Typing indicators
- [x] Online presence indicators
- [x] Delivery receipts
- [x] Unread message counter
- [x] "Scroll to bottom" button with unread badge
- [x] "Jump to first unread" button
- [x] Collapsible sidebar for mobile
- [x] Mobile-responsive layout
- [x] Connection status indicator
- [x] Reconnection banner
- [x] Auto-resizing message input textarea

## Security & Anti-Spam
- [x] Content Security Policy headers
- [x] Server-side rate limiting (10 messages per 5 seconds)
- [x] Client-side rate limiting
- [x] Repeated message detection (prevents 3+ identical messages)
- [x] Password strength requirements (min 6 characters)
- [x] Username validation (2-32 characters)
- [x] Group code validation (2-32 characters)
- [x] Filename sanitization for uploads
- [x] CSRF token validation for state-changing operations
- [x] Session authentication for Socket.IO connections

## Group Owner Controls
- [x] Kick members from group
- [x] Disband group
- [x] Clear chat history (or allow members to clear)
- [x] Delete any message in owned groups
- [x] Configure group settings (allow_member_clear)

## Database & Persistence
- [x] SQLite database with better-sqlite3
- [x] WAL mode for better concurrent performance
- [x] Safe database migrations
- [x] Persistent session storage (sessions.db)
- [x] Support for Railway Volumes via DB_PATH env var
- [x] Auto-generated session secret with database persistence
- [x] Database schema includes: users, group_chats, group_members, messages, _config

## Real-time Features (Socket.IO)
- [x] Real-time message delivery
- [x] Typing indicators (start/stop)
- [x] Online presence tracking
- [x] User join/leave notifications
- [x] Member kicked notifications
- [x] Group disbanded notifications
- [x] Chat cleared notifications
- [x] Message deleted notifications
- [x] Group renamed notifications
- [x] User profile updated notifications
- [x] Presence updates on join/disconnect

## Deployment & Configuration
- [x] Railway.app one-click deployment
- [x] Environment variable configuration (SESSION_SECRET, PORT, DB_PATH, ADMIN_SECRET)
- [x] Auto-detection of production environment
- [x] Node.js version requirement (>=18.0.0)
- [x] Railway.json deployment configuration
- [x] Static file serving from /public directory
- [x] Trust proxy configuration for Railway

## Additional Features
- [x] Audio notification sound (Web Audio API)
- [x] Automatic key refresh on encryption key changes
- [x] Session cleanup on user deletion
- [x] Membership cleanup on group disbanding
- [x] Message history export with encryption status indicators
- [x] Reply preview bar with cancel button
- [x] Whisper recipient picker UI
- [x] Group code display and copy functionality
- [x] User logout functionality
