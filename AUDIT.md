# Holocaust Network Auditor — Full Audit Report

## 1. ARCHITECTURE OVERVIEW

### Current Structure
```
Holocaust/
├── main.py                 # Entry point
├── core/                   # Infrastructure (i18n, logger, config, interface manager)
├── models/                 # Data models (Device, Vulnerability, Credential, etc.)
├── modules/                # Scan engines (LAN, WiFi, Vuln, Camera, PC, MSF bridge)
├── workers/                # QThread workers for async operations
├── gui/
│   ├── main_window.py      # Central hub (974 lines — too big)
│   ├── tabs/               # 7 tab widgets
│   └── widgets/            # Reusable widgets (graph, cards, panels)
├── database/               # SQLite manager + CVE cache
├── reports/                # HTML/PDF report generator
└── assets/styles/          # QSS theme
```

### Window Layout
```
┌─────────────────────────────────────────────────────────┐
│ [Sidebar 200-350px] │ [TabWidget (7 tabs)]              │
│  Targets            │  Dashboard / Interfaces / LAN /   │
│  [All][Scan][MSF]   │  Vulns / Metasploit / Reports /   │
│  [Del] [count]      │  Settings                         │
│  ┌─────────────┐    │  ┌──────────────────────────────┐ │
│  │ DeviceCard   │    │  │ Main tab content             │ │
│  │ DeviceCard   │    │  ├──────────────────────────────┤ │
│  │ ...          │    │  │ DetailPanel (hidden by def.) │ │
│  └─────────────┘    │  └──────────────────────────────┘ │
├─────────────────────┴───────────────────────────────────┤
│ [Logs ▾] [filter] [lines] [Clear]                       │
├─────────────────────────────────────────────────────────┤
│ StatusBar: Ready | Hosts: 0 | Vulns: 0 | MSF: disconn. │
└─────────────────────────────────────────────────────────┘
```

---

## 2. CRITICAL ISSUES (Must Fix)

### 2.1 Security

| # | File | Line | Issue | Impact |
|---|------|------|-------|--------|
| S1 | vulns_tab.py | 187 | HTML injection: CVE title/description inserted into HTML via `setHtml()` without escaping | XSS if malicious CVE data |
| S2 | interface_manager.py | — | Interface names passed to `subprocess` without sanitization | Command injection |
| S3 | credential.py | — | Passwords stored in plaintext in memory and DB | Credential exposure |
| S4 | settings.ini | — | API keys and passwords in plaintext config file | Secret leakage |
| S5 | camera_auditor.py | 67 | SSL verification disabled (`verify=False`) | MITM attacks |
| S6 | db_manager.py | — | SQL queries with LIKE on user input without parameterization | SQL injection potential |

### 2.2 Stub/Dead Code (Features That Look Working But Do Nothing)

| # | File | Line | What's Broken |
|---|------|------|---------------|
| D1 | metasploit_tab.py | 225-227 | `_on_search()` = `pass` — Search button does nothing |
| D2 | metasploit_tab.py | 246-247 | `_on_refresh_sessions()` = `pass` — Refresh Sessions does nothing |
| D3 | detail_panel.py | 88-90 | Notes text field has no save mechanism — notes lost on navigation |
| D4 | interfaces_tab.py | 48 | Refresh button created but never connected to any signal |
| D5 | camera_auditor.py | — | `check_rtsp()` generates URL but doesn't actually test RTSP stream |
| D6 | pc_auditor.py | — | RDP/SSH credential testing not implemented |

### 2.3 Crashes & Blocking

| # | File | Line | Issue |
|---|------|------|-------|
| C1 | metasploit_tab.py | 221 | `int(text or "55553")` crashes on non-numeric port input |
| C2 | settings_tab.py | 219-347 | `subprocess.run()` for DB status checks blocks UI thread — freezes window |
| C3 | main_window.py | 966-970 | Worker cleanup only waits 3s — long scans may leak threads |
| C4 | reports_tab.py | 90-92 | `xdg-open` / `open` called on Windows — always crashes |
| C5 | main_window.py | 452-459 | No try-catch around FullScanWorker creation — init failure = crash |

### 2.4 Race Conditions & Thread Safety

| # | File | Issue |
|---|------|-------|
| T1 | workers/ | Device objects passed through signals without copying — GUI reads while worker writes |
| T2 | workers/ | `_abort` flag is a plain bool, not atomic — no synchronization |
| T3 | workers/ | No thread pool — each scan creates a new QThread |
| T4 | interfaces_tab.py | Interface selection can change between UI refresh and button press |

---

## 3. MODULE COMPLETENESS

### 3.1 Scanning Modules

| Module | Status | Completeness | Key Problems |
|--------|--------|-------------|--------------|
| lan_scanner | Works | 60% | Hosts scanned sequentially (no parallelism), no ARP scan mode |
| wifi_scanner | Partial | 30% | `time.sleep()` blocks, no deauth, no WPS, no handshake capture |
| vulnerability_scanner | Works | 55% | Hardcoded NSE scripts, no Exploit-DB, no custom script support |
| camera_auditor | Partial | 50% | RTSP not tested, no ONVIF, no snapshot capture |
| pc_auditor | Partial | 45% | No real brute-force, no lateral movement, no pass-the-hash |
| metasploit_bridge | Partial | 35% | No module search, no session management, no payload generation |
| device_classifier | Works | 40% | All databases hardcoded, no IEEE OUI file, poor heuristics |

### 3.2 Missing Capabilities (For Professional Tool)

**Reconnaissance:**
- DNS enumeration / zone transfer
- SNMP enumeration (community string brute)
- LDAP / Active Directory recon
- Traceroute / hop analysis
- SSL/TLS cipher audit
- HTTP method enumeration
- Banner grabbing with analysis
- OS fingerprinting via multiple methods

**Attack:**
- WiFi deauthentication / WPS attacks
- Credential stuffing / dictionary brute-force
- Kerberos attacks (AS-REP roasting, Kerberoasting)
- Pass-the-hash / relay attacks
- Web vuln scanning (SQLi, XSS, path traversal)
- Payload generation (msfvenom integration)
- Post-exploitation (persistence, lateral movement)
- Pivoting through compromised hosts
- ARP spoofing / MITM

**Infrastructure:**
- Scan queuing (multiple scans in parallel)
- Pause/Resume scanning
- Scan scheduling (cron-like)
- Result diff (compare scans over time)

---

## 4. DATA MODELS

| Model | Issues |
|-------|--------|
| Device | `risk_score` too simplistic (linear), no confidence score, no IPv6, no last_seen timestamp |
| Vulnerability | No CWE, no CVSS vector string, no remediation steps, no false positive flag |
| Credential | Plaintext passwords, no encryption, no TTL/expiration |
| NetworkInterface | CIDR calculation bug, no IPv6, no interface speed/MTU |
| ScanResult | No audit trail, no raw nmap commands stored, no scan duration |
| ScanConfig | No validation on port_range format, no profiles (save/load presets) |

---

## 5. DATABASE & CONFIG

| Issue | Detail |
|-------|--------|
| No ORM | Raw SQL queries throughout `db_manager.py` |
| No migrations | Schema changes = manual DB recreation |
| No foreign keys | Data integrity not enforced |
| No versioning | No DB schema version tracking |
| requirements.txt | No version pinning; `pymsf 0.1.0` (2017), `xhtml2pdf` abandoned |
| No .env | Secrets stored in `settings.ini` plaintext |

---

## 6. GUI & UX DESIGN ISSUES

### 6.1 Layout Problems

| # | Area | Problem |
|---|------|---------|
| L1 | Dashboard top bar | 4 controls crammed in one row — tight on <1440px screens |
| L2 | Dashboard | Auto-vuln/auto-report checkboxes detached from Scan button, tiny gray text — easy to miss |
| L3 | Sidebar toolbar | Buttons `All/Scan/MSF/Del` are abbreviations without icons, 26px height — hard to click |
| L4 | Sidebar | `Del` button (dangerous) has no confirmation dialog for batch remove |
| L5 | Sidebar | Selection count label 30px width — "100" won't fit |
| L6 | Tab bar | 7 tabs — won't fit on small screens, no logical grouping |
| L7 | Detail Panel | Opens at bottom, steals space, only visible on certain tabs |
| L8 | Settings | Long vertical form with no internal tabs/sections |

### 6.2 Empty States & Feedback

| # | Area | Problem |
|---|------|---------|
| E1 | Network Graph | Shows black void when empty — no "Start a scan" placeholder |
| E2 | StatCards | Show "0" before any scan — no distinction "not scanned" vs "0 results" |
| E3 | All tables | Empty tables show blank space — no "No data" message |
| E4 | Copy CVE | Copies to clipboard with no toast/feedback |
| E5 | Button operations | No confirmation of success (interface up/down, scan start) |
| E6 | Scan finish | No summary notification — just status bar text change |

### 6.3 Missing UI Features

| # | Feature | Impact |
|---|---------|--------|
| M1 | No MenuBar | No File/Edit/Scan/Tools/Help — no discoverability |
| M2 | No keyboard shortcuts | Can't Ctrl+F search, F5 refresh, Space select |
| M3 | No icons | All device types use text letters (R, W, L, C) instead of SVG icons |
| M4 | No drag & drop | Can't drag device to MSF tab or group |
| M5 | No splitter persistence | Splitter sizes reset on restart |
| M6 | No undo | No action can be undone |
| M7 | No responsive layout | UI breaks on 1280px width |
| M8 | No graph mini-map | Graph unmanageable with 100+ devices |
| M9 | No CSV/JSON export | Only HTML/PDF reports, no data export |
| M10 | No scan pause/resume | Can only abort, not pause |
| M11 | No device grouping/tags | Can't organize 100+ devices |
| M12 | No timeline | No history of device state changes |

### 6.4 Theme Issues

| # | Problem | Detail |
|---|---------|--------|
| TH1 | Selection invisible | `#1a2530` on `#0b0b0f` — ~5% brightness difference |
| TH2 | Single accent color | Everything interactive is `#5a7ea0` — no visual hierarchy |
| TH3 | Inline styles override QSS | DeviceCard, LogPanel, NetworkGraph all use `setStyleSheet()` — theme can't be changed |
| TH4 | QDialog/QMessageBox unstyled | Default white background breaks dark theme |
| TH5 | Alternate row too subtle | `#0f0f14` vs `#0b0b0f` — barely visible |
| TH6 | Disabled state too faint | `#404050` text on `#0b0b0f` — poor contrast |
| TH7 | No light theme | Only dark theme, no switching option |

### 6.5 Per-Screen Design Issues

**Dashboard:**
- Graph empties on clear but shows no placeholder
- StatCards take 90px vertical space even when all zeros
- No scan ETA indicator (Quick=1min? Deep=1hr?)

**Interfaces & Wi-Fi:**
- Refresh button not connected
- 6 buttons in a row without icons — all look identical
- No indication which interface is selected for operations
- Wi-Fi password field always visible even for open networks

**LAN Scanner:**
- Duplicates target input + scan button from Dashboard
- Different targets possible on Dashboard vs LAN tab — confusing
- `Phones` filter uses magic string instead of enum
- No pagination for 500+ devices

**Vulnerabilities:**
- Detail panel 200px fixed — not enough for long CVE descriptions
- `Exploitable Only` button has no checked-state styling
- Per-row `Exploit` buttons + bottom `Launch Best Exploit` = redundant
- No CVE links to NVD/MITRE
- No EPSS score display

**Metasploit:**
- 3 vertical sections via splitter — overloaded
- No LHOST/LPORT fields — critical for reverse shells
- Default password "msf" pre-filled in password field
- Search and Sessions completely non-functional

**Reports:**
- Emptiest tab — 3 buttons and blank preview
- `xdg-open` on Windows — broken
- No template selection, no custom branding
- QTextEdit for HTML preview renders poorly (no CSS support)

**Settings:**
- DB checks block UI thread
- Hardcoded Linux paths (`/usr/share/nmap/...`) — fail on Windows
- Language change requires restart
- No backup/restore configuration

---

## 7. IMPLEMENTATION PLAN

### Phase 1: Fix Critical (Stability & Security)
1. **S1**: Escape HTML in vulns_tab detail panel
2. **S2**: Sanitize interface names before subprocess calls
3. **C1**: Validate port input (use QSpinBox or try/except)
4. **C2**: Move DB status checks to background worker
5. **C4**: Fix `_open_folder` for Windows (`os.startfile` / `QDesktopServices`)
6. **D1/D2**: Implement MSF search and session refresh via bridge
7. **D4**: Connect Refresh button on Interfaces tab
8. **T1**: Copy Device objects before sending through signals
9. **T2**: Use threading.Event or QAtomicInt for abort flag
10. **C3**: Proper worker cleanup with timeout + force terminate
11. **L4**: Add confirmation dialog for batch remove

### Phase 2: Complete Modules
1. Parallel host scanning (thread pool / asyncio)
2. Real RTSP check with timeout in camera_auditor
3. Credential brute-force with dictionary + rate limiting
4. MSF module search via RPC API
5. MSF session list/interact via RPC API
6. DNS/SNMP/SSL enumeration modules
7. Notes persistence to database
8. LHOST/LPORT fields in MSF tab

### Phase 3: UX Overhaul
1. Add MenuBar with File/Scan/Attack/Tools/Help
2. Consolidate 7 tabs → 4 tabs (Dashboard, Recon, Attack, Report)
3. Add empty states / placeholders for all empty views
4. Add toast notification system
5. Add keyboard shortcuts (F5, Ctrl+F, Ctrl+S, Space, Delete)
6. Replace text letters with SVG icons for device types
7. Fix theme: better selection contrast, styled QDialog/QMessageBox
8. Move inline styles to QSS where possible
9. Add scan ETA indicator
10. Save/restore splitter sizes + window geometry

### Phase 4: Professional Features
1. Scan pause/resume
2. Scan queue (multiple concurrent scans)
3. CSV/JSON export
4. Device grouping/tags
5. Scan diff (compare before/after)
6. Graph improvements: force-directed layout, subnet clustering, mini-map
7. Drag & drop devices to MSF/groups
8. Scan profiles (save/load presets)
9. OUI database for vendor lookup
10. Report templates + custom branding

### Phase 5: Advanced Attack Capabilities
1. ARP spoofing / MITM module
2. WiFi deauth + handshake capture
3. WPS brute-force
4. Kerberos/AD attack modules
5. Web vulnerability scanner (SQLi, XSS)
6. msfvenom payload generation UI
7. Post-exploitation module framework
8. Pivoting through compromised hosts
9. Credential relay attacks
10. Attack chain automation (recon → exploit → post-exploit)

---

## 8. PRIORITY MATRIX

```
               IMPACT
          Low    Med    High
    Low  │ TH7  │ M8   │ M9   │
EFFORT   │      │ M12  │ M11  │
    Med  │ TH5  │ D3   │ D1   │
         │ E4   │ D4   │ D2   │
    High │ M4   │ L6   │ S1   │
         │ M6   │ Phase4│ C2   │
```

**Quick Wins (High Impact, Low Effort):**
- S1: HTML escaping (1 line fix)
- C1: Port validation (3 line fix)
- C4: Windows folder open (2 line fix)
- D4: Connect Refresh button (1 line fix)
- L4: Batch remove confirmation (5 line fix)
- E1-E3: Empty state labels (10 min each)

**High Value (High Impact, Medium Effort):**
- D1/D2: MSF search + sessions (need bridge API)
- C2: Async DB checks (refactor to worker)
- Phase 2 items: Complete core modules
- L6: Tab consolidation (restructure UI)

**Strategic (High Impact, High Effort):**
- Phase 3: Full UX overhaul
- Phase 5: Attack capabilities
- Thread pool architecture
- Graph force-directed layout
