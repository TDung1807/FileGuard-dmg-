# FileGuard

> **Drag-and-drop file security scanner for macOS** — combines Google's Magika AI for local file-type detection with VirusTotal's cloud threat intelligence to instantly reveal whether a file is safe, suspicious, or malicious.

---


## Overview

FileGuard is a native macOS application built with SwiftUI. It is designed for developers, security researchers, and power users who regularly download or receive files and want a quick, reliable way to verify their safety before opening them.

Unlike simple antivirus tools that rely solely on signature databases, FileGuard uses a **two-layer approach**:

1. **Local deep inspection** (offline) — Google's Magika AI model detects the *true* content type of the file based on its binary content, and compares it against the declared file extension. A `.pdf` that is actually a Windows executable is an immediate red flag.

2. **Cloud reputation lookup** (online) — The file's SHA-256 hash is submitted to the VirusTotal API, which aggregates results from over 70 antivirus engines. No file bytes are sent unless the hash is unknown *and* the user explicitly chooses to upload.

---

## Features

| Feature | Details |
|---|---|
| 🎯 Drag & Drop | Drop any file onto the app to begin scanning immediately |
| 🔍 AI File-Type Detection | Powered by Google Magika — detects true content type from binary data |
| 🛡️ Extension Mismatch Detection | Catches files disguised with a fake extension (e.g., malware as `.jpg`) |
| ☁️ VirusTotal Integration | Queries 70+ antivirus engines via SHA-256 hash lookup |
| 📤 File Upload | Optionally upload unknown files directly to VirusTotal for first-time analysis |
| ⚡️ Smart Duplicate Detection | Detects files scanned before (by hash) and shows the previous result instantly |
| 🕐 Persistent Scan History | Remembers up to 200 previous scans across sessions |
| 🔔 macOS Notifications | Sends a system notification when analysis completes in the background |
| 📋 Report Export | One-click copy of a full structured scan report to clipboard |
| ⚙️ Settings | Configure your VirusTotal API key and custom Magika binary path |

---

## How It Works

### Analysis Pipeline

When a file is dropped onto FileGuard, it goes through a sequential 5-step pipeline:

```
[File Dropped]
      │
      ▼
┌─────────────────────┐
│  Step 1: SHA-256    │  ← CryptoKit, memory-efficient 8MB chunked reads
│  Hashing            │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Step 2: Duplicate  │  ← Hash matched against persisted scan history
│  Check              │
└────────┬────────────┘
         │ (no duplicate / user chose "Scan Anyway")
         ▼
┌─────────────────────┐
│  Step 3: Magika     │  ← Local subprocess call, JSON output parsed
│  Local Analysis     │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Step 4: VirusTotal │  ← REST API v3, hash-based lookup (no upload by default)
│  Cloud Lookup       │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Step 5: Verdict    │  ← Deterministic rules combining Magika + VT results
│  Engine             │
└─────────────────────┘
         │
         ▼
  [Result Displayed]
```

---

### Step 1 — SHA-256 Hashing

**Service:** `HashingService`  
**Technology:** Apple CryptoKit (`SHA256`)

The file is hashed using SHA-256. To support very large files without exhausting memory, the file is read in **8 MB chunks** rather than loading it entirely into RAM. The result is a 64-character lowercase hex string (e.g., `e3b0c44298fc1c149...`).

---

### Step 2 — Duplicate Detection

**Service:** `HistoryStorageService`

The computed hash is searched against the in-memory scan history (which is loaded from disk on launch). If a matching previous scan is found, the pipeline is **paused** and the user is shown a dialog:

- **"View Previous Result"** — Instantly shows the previous scan without re-running the pipeline.
- **"Scan Anyway"** — Re-runs the full pipeline (Step 3 onwards) and creates a new history entry.
- **"Cancel"** — Dismisses without action.

This prevents redundant API calls and speeds up re-scanning already known files.

---

### Step 3 — Magika Local Analysis

**Service:** `MagikaService`  
**Technology:** Google Magika CLI (Python, runs as a subprocess)

FileGuard calls the `magika` CLI binary with `--json` flag and parses the structured JSON output. The service resolves the binary path using a **4-step resolution chain**:

1. Check `UserDefaults` for a user-configured path (set in Settings).
2. Run `/usr/bin/env which magika` to find it in `PATH`.
3. Probe common fallback locations:
   - `~/.local/bin/magika`
   - `/usr/local/bin/magika`
   - `/opt/homebrew/bin/magika`
   - `~/.pyenv/shims/magika`
4. Throw `magikaNotFound` if all attempts fail.

A **30-second timeout** is enforced. If Magika does not complete within this window, the subprocess is terminated and an error is thrown.

**Extension Mismatch Check:** After getting the detected content label from Magika, FileGuard compares it against the file's declared extension using a comprehensive lookup table covering 100+ file types across documents, images, audio, video, archives, executables, source code, and more. A mismatch (e.g., a file named `invoice.pdf` that Magika identifies as `pebin` — a Windows executable) raises an immediate **Suspicious** verdict.

---

### Step 4 — VirusTotal Cloud Lookup

**Service:** `VirusTotalService`  
**API:** VirusTotal v3 REST API

The SHA-256 hash computed in Step 1 is sent to `https://www.virustotal.com/api/v3/files/{hash}` via a standard `GET` request with the user's API key in the `x-apikey` header.

**Response handling:**

| HTTP Status | Meaning | Action |
|---|---|---|
| `200 OK` | Hash found in database | Parse antivirus engine stats (malicious, suspicious, harmless, undetected counts) |
| `404 Not Found` | File never scanned by VT | Return `.notFound` — user may optionally upload |
| `401 Unauthorized` | Invalid API key | Throw `invalidAPIKey` error |
| `429 Too Many Requests` | Rate limit exceeded | Throw `rateLimitExceeded` error |

**No file bytes are sent during the hash lookup.** The file's privacy is preserved — VirusTotal only receives its hash fingerprint.

**Upload Flow (Optional):** If the hash returns `404`, the user can choose to upload the file directly. FileGuard then:
1. Detects file size — files under 32 MB use the standard upload endpoint; files between 32 MB and 650 MB request a special large-file upload URL first.
2. Uploads the file as `multipart/form-data`.
3. Polls the analysis endpoint every **15 seconds** for up to **5 minutes**.
4. Re-fetches the full stats once analysis completes.

---

### Step 5 — Verdict Engine

**Logic in:** `ScanResult.computeVerdict(magika:vt:)`

The final verdict is determined by a simple, deterministic rule set:

```
IF VirusTotal detected malicious engines > 0       → 🔴 MALICIOUS
ELSE IF file extension mismatches detected content → 🟡 SUSPICIOUS  
ELSE IF VirusTotal detected suspicious engines > 0 → 🟡 SUSPICIOUS
ELSE IF file hash not found on VirusTotal          → 🟡 SUSPICIOUS
ELSE                                                → 🟢 SAFE
```

> **Note:** A file whose hash is not found on VirusTotal (`notFound`) is treated as **Suspicious** — not Safe — because the absence of data is itself a risk signal. The user should consider uploading for full analysis.

---

## Architecture

```
FileGuard/
├── FileGuardApp.swift          # App entry point, Settings window registration
├── Models.swift                # All data models, enums, error types
│
├── ViewModels/
│   └── FileAnalyzerViewModel.swift   # @MainActor — central state coordinator, pipeline orchestrator
│
├── Views/
│   ├── ContentView.swift       # Root layout: left pane (drop + history) + right pane (result)
│   ├── DropZoneView.swift      # Drag-and-drop target
│   ├── ResultPanelView.swift   # Detailed result display, upload prompt, copy button
│   ├── ScanHistoryRowView.swift # Individual row in the history list
│   └── SettingsView.swift      # API key + Magika path configuration
│
└── Services/
    ├── HashingService.swift         # actor — SHA-256 chunked file hashing (CryptoKit)
    ├── MagikaService.swift          # actor — Magika subprocess execution and output parsing
    ├── VirusTotalService.swift      # actor — VT API hash lookup, file upload, polling
    ├── HistoryStorageService.swift  # actor — JSON persistence in ~/Library/Application Support/FileGuard/
    └── NotificationService.swift   # UNUserNotificationCenter integration
```

**Design patterns used:**
- **MVVM** — Views observe `FileAnalyzerViewModel` via `@StateObject`/`@ObservedObject`
- **Swift Actors** — All services are actors to ensure thread-safe concurrent access
- **Structured Concurrency** — `async/await` and `Task` throughout; cancellation-aware via `Task.checkCancellation()`
- **Atomic file writes** — History JSON is written with `.atomic` option to prevent data corruption

---

## Requirements

| Requirement | Minimum |
|---|---|
| macOS | 13.0 Ventura or later |
| Xcode | 15.0 or later (to build from source) |
| Python | 3.8+ (for Magika) |
| Magika | Latest (`pip install magika`) |
| VirusTotal API Key | Free account at [virustotal.com](https://www.virustotal.com/gui/join-us) |
| Internet connection | Required for VirusTotal lookup (Magika works offline) |

---

## Installation

### Option A — Install from DMG (Recommended)

1. Download `FileGuard_Installer.dmg` from the Releases page.
2. Open the `.dmg` file.
3. In the window that appears, drag **FileGuard.app** to the **Applications** shortcut.
4. Eject the DMG.
5. Open FileGuard from your Applications folder.
6. On first launch, macOS may show a warning since the app is not from the App Store — right-click the app and choose **Open**, then confirm.

### Option B — Build from Source

```bash
# Clone the repository
git clone <repo-url>
cd FileGuard

# Open in Xcode
open FileGuard.xcodeproj
```

1. Select the `FileGuard` scheme and your Mac as the target.
2. Press `⌘R` to build and run, or `⌘B` to build only.
3. The built `.app` will be in `Products/FileGuard.app` (right-click in Xcode navigator → Show in Finder).

> **Note:** Sandboxing is disabled in this app (required for Magika subprocess execution). This means it cannot be distributed via the Mac App Store in its current form.

---

## Setup & Configuration

### 1. Install Magika

Magika is Google's AI-powered file-type identification tool. FileGuard requires the `magika` CLI to be installed.

```bash
pip install magika
```

Verify the installation:
```bash
magika --version
```

FileGuard will auto-detect Magika if it is in your `PATH`. If it is installed in a non-standard location (e.g., inside a Python virtual environment), you can set the path manually in Settings.

### 2. Get a VirusTotal API Key

1. Sign up for a free account at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us).
2. Go to your profile and copy your **API Key**.

> **Free tier limits:** 4 lookups per minute, 500 per day. This is sufficient for regular personal use.

### 3. Enter Settings in FileGuard

1. Open FileGuard.
2. Press `⌘,` (Command + Comma) to open Settings, or click the ⚙️ gear icon in the bottom-left of the app.
3. Paste your **VirusTotal API Key** in the API Key field.
4. (Optional) If Magika was not auto-detected, click **Browse…** to manually select the `magika` binary, or paste the path directly.
5. Close the Settings window — changes are saved automatically.

---

## Usage Guide

### Scanning a File

1. Launch FileGuard.
2. **Drag any file** from Finder and drop it onto the drop zone (the large area in the center of the app).
3. The progress bar will show the current step:
   - `Computing SHA-256 hash...`
   - `Running Magika local analysis...`
   - `Querying VirusTotal...`
   - `Analysis complete`
4. When complete, the **Result Panel** slides in from the right.

> Alternatively, you can **click** the drop zone to open a file picker.

### Reading the Results

The Result Panel displays:

- **Overall Verdict** — `✅ Safe`, `⚠️ Suspicious`, or `🛑 Malicious` with color coding.
- **File Info** — Name, scan date, SHA-256 hash.
- **Magika Section:**
  - Detected content type (e.g., "PDF document")
  - MIME type (e.g., `application/pdf`)
  - Magika label (e.g., `pdf`)
  - Extension check — `✅ Match confirmed` or `⚠️ MISMATCH DETECTED`
- **VirusTotal Section:**
  - Detection counts: Malicious / Suspicious / Undetected / Harmless out of total engines
  - Or a warning if the hash was not found in the database

### Scan History

- The bottom of the left pane shows **Recent Scans** — a scrollable list of past results from the current and previous sessions (up to 200 entries).
- Click any history item to re-display its full result in the Result Panel.
- History is stored at `~/Library/Application Support/FileGuard/scan_history.json` and survives app restarts.
- To clear all history, open the context of the history list (future feature) or delete the JSON file manually.

### Uploading to VirusTotal

If a file's hash is not found on VirusTotal, you will see a prompt in the Result Panel:

> *"This file has never been scanned by VirusTotal. Upload it for a full analysis?"*

- Click **Upload** to send the file to VirusTotal. A warning confirms that **the file will be publicly visible** to other VirusTotal users.
- FileGuard will show progress: `Uploading...` → `Waiting for analysis...` → `Fetching results...`
- Once complete, the Result Panel updates with the full engine results.
- **Maximum upload size:** 650 MB.

### Copying a Report

Click the **Copy Report** button in the Result Panel to copy a full structured text report to your clipboard, including:

- File name and path
- Scan date and time
- All Magika analysis fields
- Full VirusTotal stats
- Overall verdict

This is useful for sharing findings or logging.

---

## Verdict Logic

| Condition | Verdict |
|---|---|
| 1+ VirusTotal engines flagged as **malicious** | 🔴 **MALICIOUS** — Do not open or execute |
| File extension **does not match** detected content type | 🟡 **SUSPICIOUS** — Extension spoofing detected |
| 1+ VirusTotal engines flagged as **suspicious** | 🟡 **SUSPICIOUS** — Manual review recommended |
| File hash **not found** in VirusTotal database | 🟡 **SUSPICIOUS** — Consider uploading for analysis |
| All checks pass | 🟢 **SAFE** |

**Verdict precedence:** Malicious > Suspicious > Safe. The worst condition wins.

---

## Data & Privacy

| Data Type | What happens |
|---|---|
| **File content** | Processed entirely **locally** by Magika. Never sent to any server by default. |
| **SHA-256 hash** | Sent to VirusTotal API for reputation lookup. Hash is a one-way fingerprint — the original file cannot be reconstructed from it. |
| **File upload** | **Only** if the hash is unknown AND the user explicitly clicks "Upload". The file will be publicly visible on VirusTotal to other users and security researchers. |
| **API Key** | Stored in macOS `UserDefaults` (on-device only). Never transmitted anywhere other than VirusTotal API requests. |
| **Scan history** | Stored locally at `~/Library/Application Support/FileGuard/scan_history.json`. Never uploaded. |

---

## File Size Limits

| Scenario | Limit |
|---|---|
| Local Magika analysis | No limit (processes in streaming chunks) |
| SHA-256 hashing | No limit (8 MB chunked reads) |
| VirusTotal hash lookup | No limit (only the hash is sent) |
| VirusTotal file upload (standard) | Up to 32 MB |
| VirusTotal file upload (large-file endpoint) | Up to 650 MB |
| Files over 650 MB | Upload rejected — hash lookup only |

---

## Supported File Types (Mismatch Detection)

FileGuard's extension mismatch engine covers the following categories:

| Category | Examples |
|---|---|
| Documents | PDF, DOCX, DOC, XLSX, XLS, PPTX, ODF, EPUB, RTF |
| Images | PNG, JPG, GIF, BMP, WEBP, SVG, ICO, TIFF, PSD, HEIC, AVIF |
| Audio | MP3, WAV, FLAC, AAC, OGG, WMA, M4A, AIFF, MIDI |
| Video | MP4, AVI, MOV, MKV, WMV, FLV, WEBM, MPEG, 3GP |
| Archives | ZIP, TAR, GZ, BZ2, XZ, RAR, 7Z, DMG, ISO, CAB, ZST |
| Executables | EXE, DLL, ELF, Mach-O (DYLIB, APP), MSI, DEB, RPM, APK, WASM |
| Text & Data | TXT, CSV, JSON, XML, YAML, TOML, INI, Markdown |
| Web | HTML, CSS, JavaScript, TypeScript, WOFF, TTF, OTF |
| Code | Python, Ruby, Java, C, C++, C#, Go, Rust, Swift, Kotlin, PHP, SQL, and more |
| Scripts | Bash/Shell, PowerShell, Batch |
| Misc | SQLite, PCAP, Java Class/JAR, SWF |

If a file has an unrecognized extension, the mismatch check is skipped (no false positives).

---

## Error Reference

| Error | Cause | Fix |
|---|---|---|
| `Magika not installed` | `magika` binary not found in PATH or configured path | Run `pip install magika`, then relaunch or set path in Settings (`⌘,`) |
| `Magika execution failed` | Binary is corrupt or subprocess timed out | Try `pip install --force-reinstall magika` |
| `No API key configured` | VirusTotal API key not entered | Open Settings (`⌘,`) and paste your key |
| `Invalid VirusTotal API key` | Key was rejected by VirusTotal (HTTP 401) | Verify your key at virustotal.com/gui/my-apikey |
| `VirusTotal rate limit reached` | More than 4 requests/min on free tier (HTTP 429) | Wait ~1 minute and try again |
| `File not found on VirusTotal` | Hash has never been submitted to VT (HTTP 404) | This is expected for new/rare files — consider uploading |
| `File is too large to upload` | File exceeds 650 MB | Hash-only lookup succeeded; upload is not possible |
| `Analysis timed out` | VT analysis did not complete within 5 minutes | Check results manually at virustotal.com |
| `Folders are not supported` | A directory was dropped instead of a file | Drop individual files only |

---

## Known Limitations

- **Not sandboxed** — FileGuard cannot be distributed on the Mac App Store in its current form. This is required to run the Magika subprocess and read arbitrary files from disk.
- **Free VirusTotal API limits** — The free tier allows 4 lookups/minute and 500/day. Heavy usage will hit rate limits.
- **Magika dependency** — Magika must be installed separately via Python/pip. FileGuard does not bundle a Python runtime.
- **No directory scanning** — Only individual files can be analyzed. Batch scanning is not currently supported.
- **VirusTotal `notFound` = Suspicious** — Brand new or extremely rare files will always show as Suspicious until uploaded and analyzed.

---

## License

FileGuard is a personal project by David.

> © 2026 FileGuard — From David with love ❤️  
> Version: 1.0 (Beta)
