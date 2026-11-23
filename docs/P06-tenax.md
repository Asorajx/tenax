# Tenax

Personal Project 06

Completed: 23 November 2026

## 1. Overview

Tenax is a Windows desktop cybersecurity toolkit that brings practical security checks together in one application.

It explains what was detected, why it matters, and what to do next. It does not give security scores or claim that anything is safe.

### 1.1 Problem

Security checks are spread across many websites, built-in Windows pages, and command-line tools. Their results are often technical, and some tools give scores or "safe" verdicts that hide how limited the check really is.

This makes it harder for ordinary users to understand what a result means and what action to take.

### 1.2 Solution

Tenax groups its tools into four areas: Password Security, Scam & Phishing, Network Tools, and Device Security. Each tool follows the same structure: an input, the findings, a plain-language explanation, and a recommended action, with technical details available when needed.

Checks run on the device wherever possible, and each tool states what leaves the device when it runs.

### 1.3 Goals

- Explain security findings in plain language
- Show what was detected, why it matters, and what to do next
- Be upfront about the limits of each check
- Keep sensitive data on the device wherever possible
- Never store or send passwords in plain text
- Read Windows settings without changing them
- Feel like a productivity tool, not conventional antivirus software

### 1.4 Features

| Feature | Description |
|---|---|
| Password Strength | Shows how difficult a password is to guess and how to make it stronger. |
| Breached Passwords | Checks whether a password appears in known data breaches by sharing only a small part of its digital fingerprint. |
| URL Checker | Inspects a link for signs of phishing without opening it. |
| QR Code Checker | Reads a QR code from an image and checks what it holds before it is scanned. |
| Email Scam Checker | Reviews an email's text for common scam indicators. |
| Email Headers | Reads SPF, DKIM, DMARC, and routing information from raw headers. |
| DNS Lookup | Queries DNS records for a domain. |
| IP Information | Shows what kind of address an IP address is, and optionally who runs it. |
| TLS Certificate | Checks a site's certificate and explains what is wrong with it, if anything. |
| Windows Security | Reads antivirus, firewall, Windows Update, Secure Boot, TPM, drive encryption, User Account Control, remote access, and automatic sign-in settings without changing them. |
| Findings Layout | Shows every result as a card with the same structure and expandable technical details. |
| Network Access Switch | Keeps network access off until the user turns it on, so connected tools cannot go online by themselves. |
| Themes and Navigation | Provides light, dark, and system themes, floating navigation grouped by workspace, keyboard shortcuts, and a responsive layout. |
| Privacy Note | Shows what leaves the device on every tool. |

## 2. Scope

### 2.1 In Scope

- Ten security tools across four areas
- A read-only Windows security check that needs no administrator rights
- A consistent findings layout with a plain-language explanation and a recommended action
- A privacy statement and a limits statement for every tool
- Light, dark, and system themes
- Keyboard shortcuts and keyboard navigation
- A Windows installer published through GitHub Releases
- Automated checks that run on every push

### 2.2 Out of Scope

The current implementation does not provide:

- Security scores or claims that anything is safe
- Changes to Windows settings
- Accounts, cloud storage, or a database (the theme is the only saved setting)
- Platforms other than Windows
- A screen lock check
- Checks of certificate revocation or website reputation

## 3. Setup & Design

### 3.1 Technology Stack

| Technology | Purpose |
|---|---|
| Tauri 2 | Desktop window, frontend and backend bridge, installer |
| React | Application interface |
| TypeScript | Interface logic and type safety |
| CSS | Styling, design tokens, and responsive layout |
| Rust | Windows checks and network calls |
| Vite | Development server and production build |
| WebView2 | Displays the interface inside the desktop window |
| zxcvbn-ts | Password strength estimation |
| jsQR | Reading QR codes from images |
| Lucide | Icons |

### 3.2 System Architecture

Tenax is two programs in one window, joined by Tauri.

- The frontend is the interface the user sees. It asks the backend to do work by calling a command, then displays the result.
- The backend is written in Rust. It reads Windows settings, makes network calls, and turns raw values into findings.
- Every tool returns results in one shared shape, defined in `finding.rs`, so the interface can show any tool's results the same way.
- The list of tools in `tools.ts` is the single source for the navigation, the Home page, the shortcuts, and each tool's privacy and limits text.
- Tauri capabilities limit what the interface is allowed to ask the backend to do.

| Area | Contains |
|---|---|
| `src/app` | The tool list, workspaces, theme logic, and QR image handling |
| `src/components` | Reusable parts such as the floating navigation, tool page, and finding card |
| `src/pages` | One file per screen |
| `src/styles` | Colours and design tokens, layout, and component styles |
| `src-tauri/src` | The Rust code, with one folder per tool |
| `src-tauri/capabilities` | What the interface is allowed to ask the backend to do |

### 3.3 Design Decisions

- Network calls and Windows checks belong in Rust, not in the interface.
- Windows logic is kept apart from the code that writes findings, so the findings can be tested with made-up values.
- If one Windows check fails, it shows "Could not check" and the others still run. A failed check is never shown as a pass.
- Every tool reports findings in one shape: status, the check's name, the state at a glance, what Tenax checked, why, what to do, and technical details.
- Network access is off every time Tenax starts, and every command that connects outside the PC goes through one switch. Turning it off also stops work that is already running.
- Tools that need the network say so, and tools that only use it when asked ask the user first.
- A QR code's contents are untrusted. They are never opened, followed, or run, and a Wi-Fi password or two-factor secret is never shown.
- Image decoding runs in a worker with a time limit, so a difficult picture cannot freeze the page.
- A collapsed, terminal-style log under the findings says what Tenax read, why, and what it found.
- Dark theme by default, with light and system options.
- Every page that has been opened stays loaded, so a tool keeps its results when the user switches pages. Results are not kept after the app is closed.
- Passwords are never stored or sent in plain text.

### 3.4 Running the Project

Tenax needs Windows 10 or 11, Node.js, Rust, and the Microsoft C++ Build Tools. WebView2 is included with Windows 11.

Install the project dependencies with `npm install`, then run `npm run tauri dev` to start the desktop application. The first run compiles the Rust code and can take several minutes.

Run the Rust tests with `cargo test` in the `src-tauri` folder.

## 4. Methodology

Tenax was built one tool at a time. Each tool follows the same steps: take an input, run the check, turn the result into findings, and show them with an explanation and a recommended action.

The Rust code is split so that the part that talks to Windows or the network is separate from the part that writes findings. This keeps the findings testable without a real system.

Each tool has a privacy note and a limits note, written alongside the tool rather than added afterwards.

GitHub Actions runs type-checking, the build, and the Rust tests on Windows for every push and pull request. Releases are made by pushing a version tag, which builds the installer and attaches it to a draft release that is published by hand.

## 5. Limitations & Risks

- Drive encryption is read from a Windows property that Microsoft does not document. On Windows 11 Home it returns no value, so the card shows "Limited" and cannot say whether the drive is protected.
- The encrypted states for drive encryption have not been seen on a real machine.
- The Tamper Protection values for "off" and "on" come from Microsoft's past documentation and have not been tested live. Only "on" has been seen.
- jsQR cannot read every QR code. It misses some non-English text, unusual text encodings, and codes that are very low contrast or under heavy noise.
- The QR Code Checker cannot see where a short link finally leads, or whether a sticker covers a genuine code.
- The URL Checker, QR Code Checker, and Email Scam Checker look for suspicious patterns. They do not visit a site or check its reputation.
- Breached Passwords relies on the Have I Been Pwned database, which may not contain every compromised password.
- IP Information uses an outside service for owner and location, and its results may be approximate.
- The TLS Certificate tool does not check revocation, and a trusted certificate does not mean a site is safe.
- A Windows Firewall that is off while a security suite reports its own firewall is shown as a note. Tenax only knows what the suite reports to Windows.
- Phone photos and printed QR codes have not been tested, because Tenax is a desktop app.

## 6. Testings and Findings

Tenax includes automated Rust tests for its tools, covering findings, parsing, and the analysis of addresses, emails, QR code contents, and DNS and IP data.

- Run `cargo test` in the `src-tauri` folder to run the automated tests.
- Run `cargo test -- --ignored --nocapture` to print the real readings from the current PC.
- Run `npm run build` to type-check and build the interface.

GitHub Actions runs the build and the Rust tests on Windows for every push, and has passed on every run checked.

The QR Code Checker was also tested in the real app with 71 generated images, covering different module sizes, awkward screenshot scaling, rotation, perspective, blur, lighting, colour, noise, JPEG compression, a logo in the middle, documents, web pages, a dark window, a 4K screenshot, and several codes in one picture. Of these, 69 were read correctly with no wrong readings. The two that were not read were a very low contrast code and a code under heavy noise. Several codes in one picture are read well up to two and mostly up to six.

Files that were not images, a GIF, a WebP, truncated and corrupt images, a header claiming 4 billion pixels, and a 40000 by 1 picture each ended with a plain message. The page never froze and nothing was sent anywhere.

The 0.2.1 installer was built, installed, started, and uninstalled on a Windows PC. The QR worker has not yet been tried inside the installed app.

The automated tests provide repeatable checks, but they do not replace manual review on different Windows editions, such as a machine with BitLocker turned on.

## 7. Challenges

| Challenge | How it was handled |
|---|---|
| Compiling Rust creates several GB of files that change on every build, which caused slow syncing and failed builds inside OneDrive. | The build files were moved outside the synced folder, since they can be recreated at any time. |
| The drive encryption property returns no value on Windows 11 Home, and the documented route needs administrator rights. | The card shows "Limited" instead of guessing, and the limit is explained to the user. |
| A failed Windows check could look like a pass. | A failed check shows "Could not check" and is never counted as a pass. |
| A Windows Firewall that is off may be intentional when a security suite is installed. | The finding is a note when another firewall is active, and a warning when none is. |
| Dropping a file onto the window is handled by Tauri and not the page. | The QR Code Checker takes an image from paste or a Choose image button instead. |
| A picture full of detail could freeze the page while a QR code was searched for. | Decoding runs in a worker with a size check up front and a 5 second limit. |
| jsQR could lose codes that sit close together. | If the whole picture gives nothing, it is cut into smaller parts and each part is searched. |
| A real progress percentage would jump and stall, because most Windows checks finish quickly and Windows Update takes longer. | The loading icon fills quickly and keeps slowing, and only the results arriving fill it completely. |
| PowerShell blocks npm scripts on some machines. | The README explains how to use `npm.cmd` or another way around it. |

## 8. Improvements

- **Release**
  - Publish the v0.2.1 draft as a full release.
  - Check the QR worker inside the installed app.
- **Windows Security**
  - Add a screen lock check.
  - Check drive encryption on a Windows Pro or Enterprise machine with BitLocker turned on.
  - Consider an optional helper for BitLocker that asks for administrator rights only when the user chooses to run it.
- **Interface**
  - Redesign the Home page now that the tools return real findings.
