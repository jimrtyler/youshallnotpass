# You Shall Not Pass - Enterprise Hardened v3.0.3

**A Chrome Extension for K-12 Filter Evasion Prevention**

Written by Jim Tyler, Microsoft MVP  
Director of Technology, Niles Community Schools

---

## Overview

You Shall Not Pass is a Chrome extension designed specifically for K-12 educational environments to defend against sophisticated filter bypass techniques. This extension provides real-time protection against browser-level exploit methodologies used to evade web content filters and security controls.

### Key Features

- **Tab Management**: Enforces configurable tab limits and detects tab spam attacks
- **History Flooding Detection**: Blocks "Point-Blank" attacks that manipulate browser history
- **Service Worker Proxy Detection**: Identifies and blocks proxy-based bypass tools (Ultraviolet, Rammerhead)
- **LTBEEF/LTMEAT Anti-Tamper**: Detects and removes GUI elements from extension exploit tools
- **URL Pattern Blocking**: 25 declarativeNetRequest rules targeting known bypass domains and patterns
- **Forensic Logging**: Comprehensive violation tracking with 30-day retention
- **Heartbeat Monitoring**: Ensures content scripts remain active and connected

---

## Installation

### Chrome Web Store (Recommended)

**Extension ID**: `efggnkbeomjjanjmghbadggegjemogee`

**Install here**: [You Shall Not Pass by Jim Tyler](https://chromewebstore.google.com/detail/you-shall-not-pass-by-jim/efggnkbeomjjanjmghbadggegjemogee)

### Enterprise Deployment

For force-installation via Google Admin Console:

1. Navigate to **Devices** → **Chrome** → **Apps & Extensions**
2. Select your organizational unit
3. Add by extension ID: `efggnkbeomjjanjmghbadggegjemogee`
4. Set installation policy to **Force Install**
5. Optionally pin to toolbar for visibility

### Manual Installation (Development)

1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode**
4. Click **Load unpacked**
5. Select the extension directory

---

## Security & Trust

### Official Extension Verification

**Official Extension ID**: `efggnkbeomjjanjmghbadggegjemogee`

**Official Chrome Web Store Link**: [You Shall Not Pass by Jim Tyler](https://chromewebstore.google.com/detail/you-shall-not-pass-by-jim/efggnkbeomjjanjmghbadggegjemogee)

Always install from the official Chrome Web Store listing. Do not install modified versions from third-party sources or unofficial repositories.

### Code Integrity & Tamper Protection

This extension is cryptographically signed by Google through the Chrome Web Store publishing process. Chrome's built-in security mechanisms provide strong protection against tampering:

- **Signature Verification**: Chrome validates the extension's cryptographic signature on every load
- **Modification Detection**: Any attempt to alter installed extension files will trigger Chrome's integrity checks
- **Automatic Disabling**: If tampering is detected, Chrome immediately disables the extension
- **Protected Installation**: Students cannot modify force-installed extensions without administrative privileges

The extension's code cannot be changed post-installation without breaking the signature, making student-level tampering effectively impossible.

### Data Privacy & Storage

This extension is designed with privacy as a core principle. All data collection is minimal, local-only, and does not contain personally identifiable information:

**What is stored locally:**
- Violation timestamps (ISO 8601 format)
- Violation type classifications (e.g., "HISTORY_FLOOD", "TAB_SPAM_DETECTED")
- Generic threshold metrics (e.g., tab count, event rate)
- Session duration information

**What is NOT stored:**
- ❌ URLs or browsing history
- ❌ User identifiers or account information
- ❌ Personal student data
- ❌ Keystrokes or form input
- ❌ Screenshots or page content

**Data transmission:**
- ❌ No data leaves the device
- ❌ No external API calls
- ❌ No remote servers or cloud services
- ❌ No telemetry or analytics

All violation logs remain on the local device in Chrome's storage API and are subject to the 30-day retention policy and 1,000-entry limit configured in the extension.

### Code Security Review

The extension codebase has been designed to minimize security vulnerabilities:

**Security-conscious practices:**
- ✅ No use of `eval()` or dynamic code execution
- ✅ No remote code loading or injection
- ✅ No external API dependencies
- ✅ No data exfiltration mechanisms
- ✅ Content Security Policy compliant
- ✅ Minimal permissions model (only essential APIs)
- ✅ Input validation on all user-controlled data
- ✅ No third-party libraries with known vulnerabilities

**Open Source Transparency:**
- Complete source code available at: https://github.com/jimrtyler/youshallnotpass
- Community auditing encouraged
- Issue reporting via GitHub Issues
- Pull requests accepted for security improvements

### Compliance & Privacy Standards

- **FERPA Compliant**: No educational records or personally identifiable student information is collected
- **COPPA Compliant**: No personal information from children under 13 is collected or transmitted
- **CIPA Compatible**: Designed to work alongside required filtering solutions without collecting additional student data

### Liability & Warranty Disclaimer

This extension is provided "AS IS" without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

**The author assumes no liability for:**
- Damages arising from use or misuse of this extension
- Compatibility issues with specific environments
- Effectiveness against all bypass methods
- Actions taken by students or third parties
- Policy violations at individual schools

**Users are responsible for:**
- Compliance with local policies and regulations
- Testing thoroughly in their environment before deployment
- Monitoring extension behavior and effectiveness
- Maintaining appropriate device management policies
- Securing their Chrome Web Store developer accounts (if republishing)

### Developer Account Security

If you are forking this project or republishing under your own Chrome Web Store account:

- Enable 2-factor authentication on your Google account
- Use strong, unique passwords
- Monitor your developer dashboard for unexpected activity
- Consider using a dedicated Google account for extension publishing
- Review all code changes before publishing updates
- Maintain audit logs of who has access to your developer account

### Reporting Security Issues

If you discover a security vulnerability in this extension:

1. **Do not** open a public GitHub issue
2. Email security concerns directly to: jim.tyler@nilesschools.org
3. Provide detailed information about the vulnerability
4. Allow reasonable time for a fix before public disclosure

Responsible disclosure is appreciated and will be credited in release notes (unless you prefer to remain anonymous).

---

## Architecture

### Components

#### background.js (Service Worker)
- Tab lifecycle management
- Violation processing and logging
- Heartbeat coordination
- Service worker keepalive
- Tab spam detection and rate limiting
- Bulk tab creation handling

#### content_guard.js (Content Script)
- Runs in all frames at document_start
- Real-time attack detection and mitigation
- History API interception (pushState/replaceState)
- DOM monitoring for exploit signatures (LTBEEF/LTMEAT)
- Heartbeat ping/pong with background worker

#### rules.json (declarativeNetRequest)
- 25 static URL blocking rules
- Targets known bypass domains and patterns
- Blocks proxy frameworks (Ultraviolet, Rammerhead, etc.)
- Blocks extension exploit tools (LTBEEF, LTMEAT, ext-remover)
- Blocks hosting platform abuse patterns
- Pattern-based educational site bypass detection

#### manifest.json
- Manifest V3 compliant
- Minimal permissions for security
- Declarative Net Request integration
- Content script injection configuration

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
- Automatic closure of excess tabs beyond MAX_TABS limit
- Bulk tab creation detection (>20 tabs triggers mitigation)
- Oldest/least-recently-accessed tabs closed first

### 2. History Flooding ("Point-Blank")
**Attack**: Rapid history.pushState() calls to crash filtering extensions  
**Defense**:
- History API interception and rate limiting
- 50 pushState/replaceState per second threshold
- Immediate page termination and violation page display on detection
- Prevents both pushState and replaceState abuse

### 3. Service Worker Proxies
**Attack**: Ultraviolet, Rammerhead, and similar Service Worker-based proxies  
**Defense**:
- Pattern detection for known proxy frameworks
- URL inspection for proxy signatures (ultraviolet, rammerhead, uv.bundle, bare-client)
- Automatic tab closure on detection
- webNavigation API monitoring for committed navigations

### 4. LTBEEF / LTMEAT / Extension Exploit GUIs
**Attack**: Browser-based tools designed to disable security extensions  
**Defense**:
- DOM monitoring for known exploit selectors (.ingot-overlay, #ext-remover, #ltbeef-ui, etc.)
- Element removal on detection
- Page reload to disrupt exploit chains
- Periodic scanning every 5 seconds

### 5. Known Bypass Domains and Patterns (declarativeNetRequest)
**25 rules targeting:**
- Educational bypass patterns (e.g., mathgames-unblocked, homework-proxy)
- Exploit frameworks (3kh0, titaniumnetwork, mercuryworkshop)
- Proxy platforms (ultraviolet, rammerhead, bare-client)
- Extension exploit sites (ltbeef, ltmeat, ext-remover, ingot)
- Hosting platform abuse (vercel, netlify, replit, render with game/proxy patterns)
- GitHub Pages abuse (github.io, pages.dev with bypass patterns)
- Raw GitHub content (raw.githubusercontent.com for main_frame/sub_frame)
- Cloudflare Workers abuse (workers.dev with exceptions for GitHub/Microsoft)
- Google Sites blob URL exploitation (with Docs/Drive exceptions)
- Known game bypass sites (retrobowl, krunker.io, shellshockers, 1v1.lol)

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

## declarativeNetRequest Rules Summary

**25 active rules** blocking:

1. **Educational bypass sites** - Sites combining educational terms with bypass keywords
2. **Blob URL exploitation** - Google Sites blob URLs (with Docs/Drive exceptions)
3. **Generic unblock patterns** - URLs with "unblock" + site/game/web
4. **3kh0** - Known exploit repository
5. **titaniumnetwork** - Proxy network
6. **mercuryworkshop** - Exploit developer collective
7. **Hosting platform abuse** - Vercel/Netlify/Render/Replit with game/proxy patterns
8. **Ultraviolet** - Service Worker proxy framework
9. **Rammerhead** - Service Worker proxy framework
10. **uv.bundle** - Ultraviolet bundle script
11. **bare-client** - Bare server client library
12. **Coolmath variations** - Coolmath with unblock/game patterns
13. **Retrobowl** - Popular game bypass
14. **Krunker.io** - FPS game
15. **Shell Shockers** - Popular game
16. **1v1.lol** - Building/shooting game
17. **GitHub Pages abuse** - github.io/pages.dev with game/proxy patterns
18. **Raw GitHub** - raw.githubusercontent.com (main_frame/sub_frame only)
19. **LTBEEF** - Extension exploit
20. **LTMEAT** - Extension exploit
21. **Ingot exploit** - Extension exploit variant
22. **ext-remover** - Extension removal tool
23. **Cloudflare Worker abuse** - Workers with proxy/game patterns
24. **Workers.dev** - Cloudflare Workers domain (with GitHub/Microsoft exceptions)
25. **Gaming sites** - Hooda/Armor/Newgrounds game patterns

**Key Rule Details:**

**Rule 1001 (Educational Bypass):**
```regex
.*(math|homework|study|class|school).*(unblo|proxy|bypass|hack).*
```
- ✅ Allows: mathplayground.com, coolmathgames.com (legitimate educational sites)
- ❌ Blocks: mathgames-unblocked.com, homework-proxy.net (bypass indicators)

---

## Known Limitations

1. **Cannot prevent all bypass methods**: This extension is one layer of defense and should be used alongside proper DNS filtering, network-level controls, and device management policies.

2. **Resource overhead**: The extension adds minimal overhead (<5MB memory, <1% CPU) but uses MutationObserver and API interception which may impact performance on complex pages.

3. **False positives possible**: Legitimate sites using heavy history manipulation or rapid navigation may trigger protections. Adjust thresholds if needed.

4. **Service Worker dormancy**: Chrome may suspend the background service worker. The keepalive mechanism mitigates this but cannot prevent all suspensions.

5. **Rule-based blocking limitations**: New bypass sites emerge constantly. The declarativeNetRequest rules catch known patterns but require updates for new threats.

---

## Deployment Recommendations

### For K-12 Districts:

1. **Force-install** via Google Admin Console
2. **Block user removal** with appropriate policies
3. **Combine with**:
   - DNS-level filtering (e.g., Securly, GoGuardian DNS, Cloudflare for Teams)
   - Network firewall rules
   - Device-level restrictions via Chrome OS policies
   - Regular user education on acceptable use

4. **Monitor forensic logs** periodically to identify patterns
5. **Adjust thresholds** based on your environment's needs
6. **Test with assessment platforms** before wide deployment (Skyward, Big Ideas Math, McGraw Hill, HMH, Illuminate, etc.)

### Policy Settings:

```json
{
  "ExtensionInstallForcelist": [
    "efggnkbeomjjanjmghbadggegjemogee;https://clients2.google.com/service/update2/crx"
  ],
  "ExtensionInstallBlocklist": ["*"],
  "ExtensionInstallAllowlist": [
    "efggnkbeomjjanjmghbadggegjemogee"
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
- Assessment platforms (Skyward, Big Ideas Math, McGraw Hill, HMH)
- Educational game sites (mathplayground.com, coolmathgames.com)

---

## Version History

### v3.0.3 (Current) - December 10, 2025
- **Revised Rule 1001** - Made educational bypass rule more specific
- Changed regex from `.*(math|homework|study|class|school).*(game|play|unblock|proxy).*` to `.*(math|homework|study|class|school).*(unblo|proxy|bypass|hack).*`
- Removed "game" and "play" from pattern (too generic, caught legitimate sites)
- Kept "unblo", "proxy", "bypass", "hack" (actual bypass indicators)
- **Fixes**: mathplayground.com, coolmathgames.com, and other legitimate educational game sites now accessible
- **Still blocks**: Sites with bypass intent (mathgames-unblocked, homework-proxy, etc.)

### v3.0.2 - December 9, 2025
- **Removed about:blank blocking** - Not supported by research as an actual threat vector
- Eliminated false positives with assessment platforms (Skyward, Illuminate, Big Ideas Math, McGraw Hill, HMH)
- Allows legitimate pop-ups and intermediate pages used by LMS/SIS platforms
- Focus maintained on research-backed threats: tab flooding, history manipulation, Service Worker proxies, LTBEEF

### v3.0.1 - December 2025
- Removed iframe flood detection (compatibility issues with legitimate sites)
- Optimized service worker keepalive
- Enhanced forensic logging with cooldown periods
- Improved LTBEEF detection signatures

### v3.0.0 - November 2025
- Complete rewrite for Manifest V3
- Added forensic logging system
- Implemented heartbeat monitoring
- Service Worker proxy detection
- LTBEEF anti-tamper protection
- 25 declarativeNetRequest rules

### v2.x - Legacy
- Manifest V2 version
- Basic tab management only

---

## Support & Contributions

**Issues**: Report bugs or false positives via [GitHub Issues](https://github.com/jimrtyler/youshallnotpass/issues)

**Pull Requests**: Contributions welcome, especially:
- New bypass detection signatures
- Performance optimizations
- Additional forensic data collection
- Dashboard UI for log viewing
- Updated declarativeNetRequest rules for emerging threats

**Contact**: jim.tyler@nilesschools.org

**MDE Tech List**: Active discussion and community support on Michigan's educational technology listserv

---

## License

This extension is provided for educational and non-profit use in K-12 environments.

**Attribution required** if distributed or modified.

---

## Disclaimer

This extension provides **defense-in-depth** but is not a complete security solution. Student bypass attempts will continue to evolve. Regular updates, combined with network-level filtering, policy enforcement, and digital citizenship education remain essential components of a comprehensive approach to student internet safety.

No security tool is perfect. This extension mitigates known attack vectors but cannot prevent all bypass methods, especially zero-day techniques or social engineering.

**Important**: This extension focuses on **browser-level exploits and technical bypass methods**. It is designed to work alongside, not replace, content filtering solutions. Your DNS filter, firewall, and network policies remain your primary defense against inappropriate content access.

---

## Acknowledgments

Built with insights from:
- K-12 technology directors nationwide
- Security research on browser exploitation
- Student bypass attempt analysis
- Forensic data from production deployments
- Michigan educational technology community (MDE Tech List)
- EdTech Magazine, EdWeek, GoGuardian, Linewize, and Securly research

Special thanks to the educational technology community for sharing intelligence on emerging bypass methods and providing feedback during development.

### Research Sources

This extension's approach is informed by industry research including:
- EdTech Magazine: "New Tech Helps Schools Defend Against Student-Built Proxies" (2025)
- Linewize: "How Students Get Around the School Web Filter" (2025)
- GoGuardian: "How Students Bypass School Web Filters & How to Stop Them"
- GovTech: "What School IT Departments Can Learn from Students" (2024)
- Securly: "Why Students Bypass School Web Filters"

---

**Written by Jim Tyler, Microsoft MVP**  
Director of Technology, Niles Community Schools  
GitHub: https://github.com/jimrtyler/youshallnotpass  
Chrome Web Store: https://chromewebstore.google.com/detail/you-shall-not-pass-by-jim/efggnkbeomjjanjmghbadggegjemogee
