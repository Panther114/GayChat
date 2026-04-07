# GayChat Changelog

This document tracks all changes to the GayChat project in a PR-based format.

---

## PR #11 — Implement explicitly listed feature tasks and bug fixes

**What changed**
- **Task 1 (Reply functionality)**: Already fully implemented - verified all functionality works (context menu, reply preview bar above input, message rendering with reply quotes, scroll to original)
- **Task 2 (Mobile toggle buttons)**: Fixed mobile UX - added visible toggle buttons (☰ and 📋) to empty state so mobile users can access sidebar and right panel when no group is selected
- **Task 3 (Page title notifications)**: Added blinking page title with unread count when tab is not focused, clears when tab gains focus
- **Task 4 (Image viewer)**: Added full-screen image viewer modal - click any image to magnify, click again or press Escape to close
- **Task 5 (File size limit & download)**: Increased file size limit from 1MB to 25GB for all file types; non-image files already auto-download when clicked
- **Task 6a (Custom profile pictures)**: Added complete profile picture system - users can upload images up to 2MB or use color + initial, displays in all avatars (messages, members, sidebar)
- **Task 6b (Clear history bug fix)**: Fixed bug where non-owners couldn't see clear chat history button even when owner enabled member clearing - moved button to new common section visible to all with permission

**What was NOT changed**
- Core messaging logic and encryption system remain unchanged
- Authentication and session management unchanged (except profile picture addition)
- Group chat core functionality unchanged
- Existing message formats preserved
- No framework additions or architectural changes
- All existing features continue to work as before

**Notes / Risks**
- Profile pictures stored as base64 data URLs in database (up to ~2.8MB per user with 2MB limit)
- File size limit increased to 25GB may impact bandwidth on some hosting platforms
- Mobile toggle buttons on empty state positioned absolutely in top corners
- All changes are fully backward compatible
- Task 1 required no code changes as it was already fully implemented

## PR #0 — Project Bootstrap

**What changed**
- Added initial documentation: readme.md, features.md, changelog.md
- Recorded all existing features in features.md
- Established documentation structure for future PR-based iteration

**What was NOT changed**
- Core logic, functionality, architecture
- Existing files unrelated to documentation
- No code modifications were made

**Notes / Risks**
- Bootstrap entry for future PR-based iteration
- README.md already existed and was comprehensive, so it was preserved as-is
- All features documented in features.md are already implemented in the codebase

**Summary of Existing Implementation** (as of PR #0)
- End-to-end encrypted group chat application
- Built with Node.js, Express, Socket.IO, and SQLite
- Client-side AES-256-GCM encryption
- Real-time messaging with typing indicators and presence
- Image and file sharing (1MB limit)
- Reply/quote and whisper mode
- Group owner controls (kick, disband, clear history)
- Mobile-responsive dark UI with glassmorphism
- Deployable to Railway.app with persistent storage support
- CSRF protection and rate limiting
- 100+ implemented features tracked in features.md
