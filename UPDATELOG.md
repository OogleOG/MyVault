# UPDATELOG

All notable changes to this project will be documented in this file.

## [2025-09-19] - v1.1.0

### Added
- **Menu bar** with: **Vault → Open Vault…, Save As…, Exit** and **Help → Help, About**.
- **Change vault location** with **Save As…**; remembers last used path via `Preferences`.
- **Unsaved changes prompt** on close/lock with **Save and Exit / Don’t Save / Cancel**.
- **Dirty indicator** (•) in window title; clears after a successful save.
- **Compact two‑column Edit/Add Entry** dialog with a **Favorite** checkbox and wide notes area; dialog is scrollable and resizable.
- **Status bar credits** (“Built by Oogle ❤️”) right‑aligned.
- **Taskbar/window icons** loaded from `icons/app-icon-<size>.png` for both the main frame and early dialogs (master password / create vault).
- **Password Generator** dialog (copies to clipboard and auto‑clears after N seconds).
- **Security Audit** dialog (Weak / Reused / Old counts with details).
- **Keyboard shortcuts**: Ctrl+S (Save), Ctrl+O (Open), Ctrl+Shift+S (Save As), Ctrl+N (New Entry), F1 (Help).
- **Title shows current vault filename** (e.g., `vault.dat`).

### Changed
- Modernized Swing UI with **FlatLaf** (rounded corners, spacing, gridless table).
- Wider, cleaner edit dialog; **Notes** now spans full width with a fixed comfortable height.
- “Change vault path” action moved to **Vault → Save As…** (instead of toolbar only), which is standard for desktop apps.
- Centralized dialog creation with `showConfirmWithIcon(...)` so all modal dialogs inherit the app icon.
- Sidebar filters integrate with search (All, Favorites, Weak, Reused, Old, tag:…).
- “Lock” now checks for unsaved changes before closing.

### Fixed
- App icon not showing on the **Enter Master Password** dialog (uses `JOptionPane.createDialog` and sets icon images explicitly).
- Very tall edit dialog on small screens (now two columns + scrollable).

### Security
- Continues to use **AES‑GCM** for data, **PBKDF2‑SHA256** key derivation; master password never stored.
- Clipboard auto‑clear after configurable seconds when copying secrets.

### Developer Notes
- New helpers: `ensureOwnerFrame()`, `showConfirmWithIcon(...)`, `setTaskbarIcon()`, `markDirty()`, `confirmCloseIfDirty()`, `saveVaultSilently()`.
- Preferences keys: `vaultPath`, `lastDir`.
- Place app icons under `src/main/resources/icons/app-icon-<size>.png` (16, 24, 32, 48, 64, 128, 256, 512).

---

## [2025-09-15] - v1.0.0 (Modern UI baseline)
- FlatLaf dark theme, toolbar, sidebar filters, gridless table.
- Clipboard auto‑clear, auto‑lock, TOTP generation, context menu for rows.
- Basic Open/Save and entry management.
