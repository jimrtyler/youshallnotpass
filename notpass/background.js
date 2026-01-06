// You Shall Not Pass - Enterprise Hardened v3.0.2
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass
// Background Service Worker
// Comprehensive defense against K-12 filter evasion ecosystem

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  MAX_TABS: 15,
  TAB_CREATION_WINDOW: 2000,        // 2 seconds
  MAX_TABS_IN_WINDOW: 5,            // Maximum tabs per window
  HEARTBEAT_INTERVAL: 5000,         // 5 seconds
  LOG_RETENTION_DAYS: 30,
  VIOLATION_COOLDOWN: 10000,        // 10 seconds between similar violations
  
  // Feature flags
  ENABLE_FORENSIC_LOGGING: true,
  ENABLE_HEARTBEAT_MONITORING: true,
  ENABLE_DNR_UPDATES: true
};

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

let tabCreationEvents = [];
let connectedPorts = new Map();
let lastViolationLog = new Map();
let extensionStartTime = Date.now();

// ============================================================================
// FORENSIC LOGGING SYSTEM
// ============================================================================

class ForensicLogger {
  static async log(violationType, details) {
    if (!CONFIG.ENABLE_FORENSIC_LOGGING) return;
    
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      violationType,
      details,
      sessionTime: Date.now() - extensionStartTime
    };
    
    // Check cooldown to prevent log flooding
    const cooldownKey = `${violationType}-${details.url || 'unknown'}`;
    const lastLog = lastViolationLog.get(cooldownKey);
    if (lastLog && (Date.now() - lastLog) < CONFIG.VIOLATION_COOLDOWN) {
      return; // Skip duplicate logs within cooldown period
    }
    lastViolationLog.set(cooldownKey, Date.now());
    
    // Store in chrome.storage
    try {
      const { violationLogs = [] } = await chrome.storage.local.get('violationLogs');
      violationLogs.push(logEntry);
      
      // Trim old logs (keep last 1000 entries or 30 days)
      const cutoff = Date.now() - (CONFIG.LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000);
      const trimmedLogs = violationLogs
        .filter(log => new Date(log.timestamp).getTime() > cutoff)
        .slice(-1000);
      
      await chrome.storage.local.set({ violationLogs: trimmedLogs });
      
      console.warn(`[FORENSIC LOG] ${violationType}:`, logEntry);
    } catch (error) {
      console.error('Failed to write forensic log:', error);
    }
  }
  
  static async getLogs(limit = 100) {
    try {
      const { violationLogs = [] } = await chrome.storage.local.get('violationLogs');
      return violationLogs.slice(-limit);
    } catch (error) {
      console.error('Failed to retrieve logs:', error);
      return [];
    }
  }
  
  static async clearLogs() {
    await chrome.storage.local.set({ violationLogs: [] });
  }
}

// ============================================================================
// HEARTBEAT & ANTI-TAMPER SYSTEM
// ============================================================================

class HeartbeatMonitor {
  static startMonitoring() {
    if (!CONFIG.ENABLE_HEARTBEAT_MONITORING) return;
    
    setInterval(() => {
      this.checkConnections();
    }, CONFIG.HEARTBEAT_INTERVAL);
  }
  
  static async checkConnections() {
    const tabs = await chrome.tabs.query({});
    const activePorts = connectedPorts.size;
    
    // If we have open tabs but no connected ports, something is wrong
    if (tabs.length > 0 && activePorts === 0) {
      await ForensicLogger.log('HEARTBEAT_FAILURE', {
        message: 'All content script connections lost',
        tabCount: tabs.length,
        suspectedAttack: 'Extension process may have been killed'
      });
    }
    
    // Log heartbeat status
    console.log(`[HEARTBEAT] Active tabs: ${tabs.length}, Connected ports: ${activePorts}`);
  }
  
  static registerPort(port) {
    const tabId = port.sender?.tab?.id;
    if (tabId) {
      connectedPorts.set(tabId, port);
      
      port.onDisconnect.addListener(() => {
        connectedPorts.delete(tabId);
      });
    }
  }
}

// ============================================================================
// TAB MANAGEMENT
// ============================================================================

async function enforceTabLimit() {
  try {
    const tabs = await chrome.tabs.query({});
    
    if (tabs.length > CONFIG.MAX_TABS) {
      const sortedTabs = tabs.sort((a, b) => {
        const timeA = a.lastAccessed || 0;
        const timeB = b.lastAccessed || 0;
        return timeA - timeB;
      });
      
      const tabsToClose = tabs.length - CONFIG.MAX_TABS;
      let closedCount = 0;
      
      for (const tab of sortedTabs) {
        if (closedCount >= tabsToClose) break;
        if (!tab.active && tab.id) {
          try {
            await chrome.tabs.remove(tab.id);
            closedCount++;
            
            await ForensicLogger.log('TAB_LIMIT_ENFORCED', {
              tabId: tab.id,
              url: tab.url,
              totalTabs: tabs.length
            });
          } catch (error) {
            console.log(`Could not close tab ${tab.id}:`, error);
          }
        }
      }
    }
  } catch (error) {
    console.error('Error enforcing tab limit:', error);
  }
}

// ============================================================================
// SPAM DETECTION
// ============================================================================

function detectTabSpam() {
  const now = Date.now();
  
  // Remove old events
  while (tabCreationEvents.length > 0 && 
         tabCreationEvents[0] < now - CONFIG.TAB_CREATION_WINDOW) {
    tabCreationEvents.shift();
  }
  
  tabCreationEvents.push(now);
  
  if (tabCreationEvents.length > CONFIG.MAX_TABS_IN_WINDOW) {
    return true;
  }
  
  return false;
}

async function handleBulkTabCreation(tabCount) {
  if (tabCount > 20) {
    await ForensicLogger.log('BULK_TAB_CREATION', {
      count: tabCount,
      suspectedAttack: 'Bookmark folder flood attack'
    });
    
    const tabs = await chrome.tabs.query({});
    const sortedTabs = tabs.sort((a, b) => (b.id || 0) - (a.id || 0));
    
    let keepCount = 0;
    const tabsToKeep = new Set();
    
    for (const tab of tabs) {
      if (tab.active) {
        tabsToKeep.add(tab.id);
      }
    }
    
    for (const tab of sortedTabs) {
      if (keepCount < CONFIG.MAX_TABS && !tabsToKeep.has(tab.id)) {
        tabsToKeep.add(tab.id);
        keepCount++;
      }
    }
    
    for (const tab of tabs) {
      if (!tabsToKeep.has(tab.id) && tab.id) {
        try {
          await chrome.tabs.remove(tab.id);
        } catch (error) {
          // Tab might be already closed
        }
      }
    }
  }
}

// ============================================================================
// SERVICE WORKER DETECTION
// ============================================================================

async function detectServiceWorkerProxy(details) {
  // Check for known proxy Service Worker patterns
  const suspiciousPatterns = [
    /ultraviolet/i,
    /rammerhead/i,
    /uv\.bundle/i,
    /bare-client/i,
    /service.*worker.*proxy/i
  ];
  
  const url = details.url || '';
  const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(url));
  
  if (isSuspicious) {
    await ForensicLogger.log('SERVICE_WORKER_PROXY', {
      url: details.url,
      tabId: details.tabId,
      suspectedProxy: 'Service Worker-based proxy detected'
    });
    
    // Attempt to close the tab
    if (details.tabId) {
      try {
        await chrome.tabs.remove(details.tabId);
      } catch (error) {
        console.error('Failed to close proxy tab:', error);
      }
    }
  }
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'SECURITY_VIOLATION':
      handleSecurityViolation(message, sender);
      break;
      
    case 'HEARTBEAT':
      sendResponse({ status: 'alive', timestamp: Date.now() });
      break;
      
    case 'GET_LOGS':
      ForensicLogger.getLogs(message.limit).then(logs => {
        sendResponse({ logs });
      });
      return true; // Will respond asynchronously
      
    case 'CLEAR_LOGS':
      ForensicLogger.clearLogs().then(() => {
        sendResponse({ success: true });
      });
      return true;
  }
});

async function handleSecurityViolation(message, sender) {
  const details = {
    subType: message.subType,
    url: message.url || sender.url,
    tabId: sender.tab?.id,
    frameId: sender.frameId,
    ...message.details
  };
  
  await ForensicLogger.log(message.subType, details);
  
  // Take action based on violation type
  switch (message.subType) {
    case 'HISTORY_FLOOD':
      // Tab already handled by content script
      break;
      
    case 'BLOB_URL_DETECTED':
      if (sender.tab?.id) {
        try {
          await chrome.tabs.remove(sender.tab.id);
        } catch (error) {
          console.error('Failed to close tab with blob URL:', error);
        }
      }
      break;
      
    case 'GAME_ENGINE_DETECTED':
      if (sender.tab?.id) {
        try {
          await chrome.tabs.remove(sender.tab.id);
        } catch (error) {
          console.error('Failed to close tab with game engine:', error);
        }
      }
      break;
  }
}

// ============================================================================
// PORT CONNECTIONS (HEARTBEAT)
// ============================================================================

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'heartbeat') {
    HeartbeatMonitor.registerPort(port);
    
    port.onMessage.addListener((msg) => {
      if (msg.type === 'ping') {
        port.postMessage({ type: 'pong', timestamp: Date.now() });
      }
    });
  }
});

// ============================================================================
// TAB EVENT LISTENERS
// ============================================================================

chrome.tabs.onCreated.addListener(async (tab) => {
  const isSpam = detectTabSpam();
  
  if (isSpam) {
    await ForensicLogger.log('TAB_SPAM_DETECTED', {
      tabId: tab.id,
      ratePerSecond: tabCreationEvents.length,
      action: 'Closing spam tab'
    });
    
    if (!tab.active && tab.id) {
      try {
        await chrome.tabs.remove(tab.id);
        return;
      } catch (error) {
        console.log('Could not close spam tab:', error);
      }
    }
  }
  
  await enforceTabLimit();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  connectedPorts.delete(tabId);
});

// ============================================================================
// WEB NAVIGATION MONITORING
// ============================================================================

chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Detect Service Worker proxies
  if (details.url) {
    await detectServiceWorkerProxy(details);
  }
});

// ============================================================================
// INITIALIZATION
// ============================================================================

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('You Shall Not Pass Enterprise v3.0.2 installed');
  
  await ForensicLogger.log('EXTENSION_INSTALLED', {
    version: '3.0.2',
    reason: details.reason,
    previousVersion: details.previousVersion
  });
  
  await enforceTabLimit();
  
  const tabs = await chrome.tabs.query({});
  await handleBulkTabCreation(tabs.length);
  
  // Start heartbeat monitoring
  HeartbeatMonitor.startMonitoring();
});

chrome.runtime.onStartup.addListener(async () => {
  console.log('You Shall Not Pass Enterprise v3.0.2 started');
  
  await ForensicLogger.log('EXTENSION_STARTUP', {
    version: '3.0.2',
    timestamp: new Date().toISOString()
  });
  
  const tabs = await chrome.tabs.query({});
  await handleBulkTabCreation(tabs.length);
  
  // Start heartbeat monitoring
  HeartbeatMonitor.startMonitoring();
});

// ============================================================================
// PERIODIC ENFORCEMENT
// ============================================================================

setInterval(async () => {
  await enforceTabLimit();
}, 10000);

// ============================================================================
// SERVICE WORKER KEEPALIVE
// ============================================================================

// Prevent service worker from going dormant during active violations
let keepAliveInterval;

function startKeepAlive() {
  if (!keepAliveInterval) {
    keepAliveInterval = setInterval(() => {
      chrome.runtime.getPlatformInfo(() => {
        // Just accessing an API keeps the service worker alive
      });
    }, 20000); // Every 20 seconds
  }
}

function stopKeepAlive() {
  if (keepAliveInterval) {
    clearInterval(keepAliveInterval);
    keepAliveInterval = null;
  }
}

// Start keepalive
startKeepAlive();

console.log('You Shall Not Pass Enterprise v3.0.2 - Background worker initialized');
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass