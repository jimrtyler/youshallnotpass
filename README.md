# You Shall Not Pass - Enterprise Hardened v3.0

**A Chrome Extension for K-12 Filter Evasion Prevention**

Written by Jim Tyler, Microsoft MVP  
Director of Technology, Niles Community Schools

---

## Overview

You Shall Not Pass is a Chrome extension designed specifically for K-12 educational environments to defend against sophisticated filter bypass techniques. This extension provides real-time protection against common exploit methodologies used to evade web content filters and security controls.

### Key Features

- **Tab Management**: Enforces configurable tab limits and detects tab spam attacks
- **About:Blank Protection**: Automatically closes suspicious about:blank tabs
- **History Flooding Detection**: Blocks "Point-Blank" attacks that manipulate browser history
- **Service Worker Proxy Detection**: Identifies and blocks proxy-based bypass tools
- **LTBEEF Anti-Tamper**: Detects and removes GUI elements from extension exploit tools
- **Forensic Logging**: Comprehensive violation tracking with 30-day retention
- **Heartbeat Monitoring**: Ensures content scripts remain active and connected

---

## Installation

### Chrome Web Store (Recommended)
Published extension ID: `eghfkiedaecinpfcdppagfaojpoblkjj`

Install directly from the Chrome Web Store (coming soon).

### Enterprise Deployment

For force-installation via Google Admin Console:

1. Navigate to **Devices** → **Chrome** → **Apps & Extensions**
2. Select your organizational unit
3. Add by extension ID: `eghfkiedaecinpfcdppagfaojpoblkjj`
4. Set installation policy to **Force Install**
5. Optionally pin to toolbar for visibility

### Manual Installation (Development)

1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode**
4. Click **Load unpacked**
5. Select the extension directory

---

## Architecture

### Components

#### background.js (Service Worker)
- Tab lifecycle management
- Violation processing and logging
- Heartbeat coordination
- Service worker keepalive

#### content_guard.js (Content Script)
- Runs in all frames at document_start
- Real-time attack detection and mitigation
- History API interception
- DOM monitoring for exploit signatures

#### manifest.json
- Manifest V3 compliant
- Minimal permissions for security
- Declarative Net Request integration

---

## Configuration

Default configuration in `background.js`:

```javascript
const CONFIG = {
  MAX_TABS: 15,
  TAB_CREATION_WINDOW: 2000,        // 2 seconds
  MAX_TABS_IN_WINDOW: 5,            // Maximum tabs per window
  HEARTBEAT_INTERVAL: 5000,         // 5 seconds
  LOG_RETENTION_DAYS: 30,
  VIOLATION_COOLDOWN: 10000,        // 10 seconds
  
  ENABLE_FORENSIC_LOGGING: true,
  ENABLE_HEARTBEAT_MONITORING: true,
  ENABLE_DNR_UPDATES: true
};
```

Content script configuration in `content_guard.js`:

```javascript
const CONFIG = {
  MAX_HISTORY_PUSHES_PER_SECOND: 50,
  HEARTBEAT_INTERVAL: 30000,        // 30 seconds
  MONITORING_ENABLED: true
};
```

---

## Attack Vectors Addressed

### 1. Tab Spam / Bookmark Folder Flooding
**Attack**: Opening hundreds of tabs simultaneously to overwhelm the browser or filter extension
**Defense**: 
- Rate limiting tab creation (5 tabs per 2 seconds)
- Automatic closure of excess tabs
- Bulk tab creation detection (>20 tabs triggers mitigation)

### 2. About:Blank Exploitation
**Attack**: Using about:blank pages as intermediaries for filter bypass
**Defense**: 
- Immediate closure of about:blank tabs on creation
- Periodic scanning for about:blank pages
- Prevention of about:blank navigation

### 3. History Flooding ("Point-Blank")
**Attack**: Rapid history.pushState() calls to crash filtering extensions
**Defense**:
- History API interception and rate limiting
- 50 pushState/replaceState per second threshold
- Immediate page termination on violation

### 4. Service Worker Proxies
**Attack**: Ultraviolet, Rammerhead, and similar Service Worker-based proxies
**Defense**:
- Pattern detection for known proxy frameworks
- URL inspection for proxy signatures
- Automatic tab closure on detection

### 5. LTBEEF / Extension Exploit GUIs
**Attack**: Browser-based tools designed to disable security extensions
**Defense**:
- DOM monitoring for known exploit selectors
- Element removal on detection
- Page reload to disrupt exploit chains

---

## Forensic Logging

All violations are logged to Chrome's local storage with the following details:

- Timestamp (ISO 8601)
- Violation type
- URL and tab information
- Session time
- Attack-specific details

Logs are retained for 30 days and automatically trimmed to the most recent 1,000 entries.

### Accessing Logs

Logs can be retrieved programmatically:

```javascript
chrome.runtime.sendMessage({
  type: 'GET_LOGS',
  limit: 100
}, (response) => {
  console.log(response.logs);
});
```

### Log Retention

- Maximum 1,000 entries
- 30-day automatic expiration
- 10-second cooldown between duplicate violations (prevents log flooding)

---

## Heartbeat System

The extension maintains persistent connections between content scripts and the background service worker to detect tampering attempts.

- Content scripts establish named ports (`heartbeat`)
- Ping/pong messages every 30 seconds
- Missing connections trigger forensic logging
- Automatic reconnection on disconnection

---

## Permissions Justification

| Permission | Purpose |
|------------|---------|
| `tabs` | Tab management and lifecycle monitoring |
| `scripting` | Content script injection for protection |
| `storage` | Forensic log persistence |
| `webNavigation` | Service Worker proxy detection |
| `declarativeNetRequest` | Static rule enforcement |
| `declarativeNetRequestFeedback` | Rule matching feedback |
| `<all_urls>` | Universal content script injection |

---

## Known Limitations

1. **Cannot prevent all bypass methods**: This extension is one layer of defense and should be used alongside proper DNS filtering, network-level controls, and device management policies.

2. **Resource overhead**: The extension adds minimal overhead (<5MB memory, <1% CPU) but uses MutationObserver and API interception which may impact performance on complex pages.

3. **False positives possible**: Legitimate sites using heavy history manipulation or rapid navigation may trigger protections. Adjust thresholds if needed.

4. **Service Worker dormancy**: Chrome may suspend the background service worker. The keepalive mechanism mitigates this but cannot prevent all suspensions.

---

## Deployment Recommendations

### For K-12 Districts:

1. **Force-install** via Google Admin Console
2. **Block user removal** with appropriate policies
3. **Combine with**:
   - DNS-level filtering (e.g., Securly, GoGuardian DNS)
   - Network firewall rules
   - Device-level restrictions via Chrome OS policies
   - Regular user education on acceptable use

4. **Monitor forensic logs** periodically to identify patterns
5. **Adjust thresholds** based on your environment's needs

### Policy Settings:

```json
{
  "ExtensionInstallForcelist": [
    "eghfkiedaecinpfcdppagfaojpoblkjj;https://clients2.google.com/service/update2/crx"
  ],
  "ExtensionInstallBlocklist": ["*"],
  "ExtensionInstallAllowlist": [
    "eghfkiedaecinpfcdppagfaojpoblkjj"
  ]
}
```

---

## Development

### Building for Production

1. Update version in `manifest.json`
2. Test thoroughly in development mode
3. Package: `chrome://extensions/` → **Pack extension**
4. Upload to Chrome Web Store Developer Dashboard

### Testing

Recommended testing scenarios:
- Rapid tab creation (bookmark folder with 50+ items)
- History manipulation test pages
- Known proxy sites (blocked at network level for safety)
- Extension GUI exploit tools (in sandboxed environment)

---

## Version History

### v3.0.1 (Current)
- Removed iframe flood detection (compatibility issues with legitimate sites)
- Optimized service worker keepalive
- Enhanced forensic logging with cooldown periods
- Improved LTBEEF detection signatures

### v3.0.0
- Complete rewrite for Manifest V3
- Added forensic logging system
- Implemented heartbeat monitoring
- Service Worker proxy detection
- LTBEEF anti-tamper protection

### v2.x
- Legacy Manifest V2 version
- Basic tab management only

---

## Support & Contributions

**Issues**: Please report bugs or false positives via GitHub Issues

**Pull Requests**: Contributions welcome, especially:
- New bypass detection signatures
- Performance optimizations
- Additional forensic data collection
- Dashboard UI for log viewing

**Contact**: jim.tyler@nilesschools.org

---

## License

This extension is provided for educational and non-profit use in K-12 environments.

**Attribution required** if distributed or modified.

---

## Disclaimer

This extension provides **defense-in-depth** but is not a complete security solution. Student bypass attempts will continue to evolve. Regular updates, combined with network-level filtering, policy enforcement, and digital citizenship education remain essential components of a comprehensive approach to student internet safety.

No security tool is perfect. This extension mitigates known attack vectors but cannot prevent all bypass methods, especially zero-day techniques or social engineering.

---

## Acknowledgments

Built with insights from:
- K-12 technology directors nationwide
- Security research on browser exploitation
- Student bypass attempt analysis
- Forensic data from production deployments

Special thanks to the educational technology community for sharing intelligence on emerging bypass methods.

---

**Written by Jim Tyler, Microsoft MVP**  
Director of Technology, Niles Community Schools  
GitHub: https://github.com/jimrtyler/youshallnotpass
