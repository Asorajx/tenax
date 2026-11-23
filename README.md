# Tenax

**Download:** get the latest installer from the [Releases page](https://github.com/Asorajx/tenax/releases).

Tenax is a Windows desktop cybersecurity toolkit that brings practical security checks together in one application.

It explains what was detected, why it matters and what to do next. It does not give security scores or claim that anything is safe.

## Overview

Tenax groups its tools into four areas: Password Security, Scam & Phishing, Network Tools and Device Security. Each tool follows the same structure: an input, the findings, a plain-language explanation and a recommended action, with technical details available when needed.

Checks run on the device wherever possible, and each tool states what leaves the device when it runs.

## Goals

- Explain security findings in plain language
- Show what was detected, why it matters and what to do next
- Be upfront about the limits of each check
- Keep sensitive data on the device wherever possible
- Never store or send passwords in plain text
- Read Windows settings without changing them
- Feel like a productivity tool, not conventional antivirus software

## Features

- Desktop application for Windows
- QR code checker that reads a code from an image and checks it on the device, without opening it
- Read-only Windows security check for antivirus, firewall, Windows Update, Secure Boot, TPM, drive encryption, User Account Control, remote access and automatic sign-in
- Floating navigation grouped by workspace
- Consistent findings layout with expandable technical details
- Light, dark and system themes
- Keyboard shortcuts and keyboard navigation
- Privacy note on every tool
- Responsive layout for different window sizes

## Technology Stack

| Technology | Purpose |
| --- | --- |
| Tauri 2 | Desktop window, frontend and backend bridge, installer |
| React | Application interface |
| TypeScript | Interface logic and type safety |
| CSS | Styling, design tokens and responsive layout |
| Rust | Windows checks and network calls |
| Vite | Development server and production build |
| WebView2 | Displays the interface inside the desktop window |

## Getting started

To run Tenax locally, clone or download the repository and follow the steps below.

### Requirements

Tenax is a desktop application, so it needs more than Node.js. Install these once:

| Requirement | Purpose |
| --- | --- |
| Windows 10 or 11 | Tenax is built for Windows |
| [Node.js](https://nodejs.org/) and npm | Builds the interface |
| [Rust](https://www.rust-lang.org/tools/install) | Compiles the desktop application |
| Microsoft C++ Build Tools | Links the compiled code into a Windows program |
| WebView2 | Included with Windows 11 |

Rust and the C++ Build Tools can be installed from a terminal with winget:

```bash
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

```bash
winget install --id Rustlang.Rustup
```

Close and reopen the terminal afterwards, then check that Rust is available:

```bash
cargo --version
```

See the [Tauri prerequisites](https://tauri.app/start/prerequisites/) for more detail.

### Run the application

Open a terminal in the project folder.

Install the dependencies:

```bash
npm install
```

Start the desktop application:

```bash
npm run tauri dev
```

The first run compiles the Rust code and can take several minutes. Later runs take a few seconds.

Other useful commands:

```bash
npm run dev         # run only the interface in a browser
npm run build       # type-check and build the interface
npm run tauri build # build the Windows installer
```

Run the Rust tests from the `src-tauri` folder:

```bash
cargo test
```

If PowerShell blocks npm, use `npm.cmd` instead of `npm`.