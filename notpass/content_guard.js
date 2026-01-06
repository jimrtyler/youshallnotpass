// You Shall Not Pass - Enterprise Hardened v3.0.2
// Content Guard Script
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass
// Runs in all frames to detect and mitigate attacks in real-time

(function() {
  'use strict';
  
  // ============================================================================
  // CONFIGURATION
  // ============================================================================
  
  const CONFIG = {
    MAX_HISTORY_PUSHES_PER_SECOND: 50,
    HEARTBEAT_INTERVAL: 30000, // 30 seconds
    MONITORING_ENABLED: true
  };
  
  // ============================================================================
  // STATE
  // ============================================================================
  
  let historyMonitor = {
    count: 0,
    lastReset: Date.now(),
    violationTriggered: false
  };
  
  let heartbeatPort = null;
  
  // ============================================================================
  // HEARTBEAT SYSTEM
  // ============================================================================
  
  function initializeHeartbeat() {
    try {
      heartbeatPort = chrome.runtime.connect({ name: 'heartbeat' });
      
      heartbeatPort.onMessage.addListener((msg) => {
        if (msg.type === 'pong') {
          console.log('[HEARTBEAT] Received pong from background');
        }
      });
      
      heartbeatPort.onDisconnect.addListener(() => {
        console.warn('[HEARTBEAT] Disconnected from background');
        // Try to reconnect after delay
        setTimeout(initializeHeartbeat, 5000);
      });
      
      // Send periodic pings
      setInterval(() => {
        if (heartbeatPort) {
          try {
            heartbeatPort.postMessage({ type: 'ping' });
          } catch (error) {
            console.error('[HEARTBEAT] Failed to send ping:', error);
          }
        }
      }, CONFIG.HEARTBEAT_INTERVAL);
      
    } catch (error) {
      console.error('[HEARTBEAT] Failed to initialize:', error);
    }
  }
  
  // ============================================================================
  // HISTORY FLOODING DETECTION (Point-Blank Defense)
  // ============================================================================
  
  function handleHistoryFlood() {
    if (historyMonitor.violationTriggered) return;
    historyMonitor.violationTriggered = true;
    
    console.error('[SECURITY] HISTORY FLOOD DETECTED!');
    
    // Stop all loading
    try {
      window.stop();
    } catch (error) {
      console.error('Failed to stop window loading:', error);
    }
    
    // Report to background
    chrome.runtime.sendMessage({
      type: 'SECURITY_VIOLATION',
      subType: 'HISTORY_FLOOD',
      url: window.location.href,
      details: {
        pushStateCount: historyMonitor.count,
        threshold: CONFIG.MAX_HISTORY_PUSHES_PER_SECOND
      }
    });
    
    // Replace page content
    try {
      document.body.innerHTML = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 40px; background: #f8d7da; border: 2px solid #721c24; border-radius: 8px;">
          <h1 style="color: #721c24; margin-top: 0;">🛡️ Security Violation Detected</h1>
          <h2 style="color: #721c24;">History Manipulation Attack Blocked</h2>
          <p style="font-size: 16px; line-height: 1.6;">
            This page attempted excessive history state changes (${historyMonitor.count} per second).
            This is the "Point-Blank" attack designed to overload filtering extensions.
          </p>
          <p style="font-size: 16px; line-height: 1.6;">
            <strong>This violation has been logged and reported.</strong>
          </p>
          <p style="font-size: 14px; color: #666; margin-top: 20px;">
            Violation Type: HISTORY_FLOOD<br>
            Timestamp: ${new Date().toISOString()}<br>
            URL: ${window.location.href}
          </p>
        </div>
      `;
    } catch (error) {
      console.error('Failed to replace page content:', error);
    }
  }
  
  function initializeHistoryMonitor() {
    if (!CONFIG.MONITORING_ENABLED) return;
    
    // Intercept history.pushState
    const originalPushState = window.history.pushState;
    window.history.pushState = function(...args) {
      const now = Date.now();
      
      // Reset counter every second
      if (now - historyMonitor.lastReset > 1000) {
        historyMonitor.count = 0;
        historyMonitor.lastReset = now;
      }
      
      historyMonitor.count++;
      
      // Check threshold
      if (historyMonitor.count > CONFIG.MAX_HISTORY_PUSHES_PER_SECOND) {
        handleHistoryFlood();
        return; // Block the pushState
      }
      
      // Call original function
      return originalPushState.apply(this, args);
    };
    
    // Also intercept replaceState
    const originalReplaceState = window.history.replaceState;
    window.history.replaceState = function(...args) {
      const now = Date.now();
      
      if (now - historyMonitor.lastReset > 1000) {
        historyMonitor.count = 0;
        historyMonitor.lastReset = now;
      }
      
      historyMonitor.count++;
      
      if (historyMonitor.count > CONFIG.MAX_HISTORY_PUSHES_PER_SECOND) {
        handleHistoryFlood();
        return;
      }
      
      return originalReplaceState.apply(this, args);
    };
  }
  
  // ============================================================================
  // ANTI-LTBEEF DOM MONITORING
  // ============================================================================
  
  function detectLTBEEFGUI() {
    // Check for known LTBEEF GUI elements
    const suspiciousSelectors = [
      '.ingot-overlay',
      '#ext-remover',
      '#ltbeef-ui',
      '[data-exploit="ltbeef"]',
      '.spork-gui'
    ];
    
    for (const selector of suspiciousSelectors) {
      const element = document.querySelector(selector);
      if (element) {
        console.warn('[SECURITY] LTBEEF GUI detected:', selector);
        
        chrome.runtime.sendMessage({
          type: 'SECURITY_VIOLATION',
          subType: 'LTBEEF_GUI_DETECTED',
          url: window.location.href,
          details: {
            selector,
            elementHTML: element.outerHTML.substring(0, 200)
          }
        });
        
        // Remove the element
        try {
          element.remove();
        } catch (error) {
          console.error('Failed to remove LTBEEF GUI element:', error);
        }
        
        // Reload to disrupt exploit
        setTimeout(() => {
          window.location.reload();
        }, 100);
        
        return true;
      }
    }
    
    return false;
  }
  
  // ============================================================================
  // INITIALIZATION
  // ============================================================================
  
  function initialize() {
    console.log('[CONTENT GUARD] Initializing protection...');
    
    try {
      initializeHeartbeat();
      initializeHistoryMonitor();
      
      // Check for LTBEEF GUI periodically
      setInterval(detectLTBEEFGUI, 5000);
      
      console.log('[CONTENT GUARD] Protection active');
    } catch (error) {
      console.error('[CONTENT GUARD] Initialization error:', error);
    }
  }
  
  // Start protection as early as possible
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }
  
  // Also run immediately for document_start injection
  initialize();
  
})();
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass