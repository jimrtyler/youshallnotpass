// You Shall Not Pass - Enterprise Hardened v3.0
// Google Sites Inspector
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass
// Detects blob URL obfuscation and embedded game content

(function() {
  'use strict';
  
  // ============================================================================
  // CONFIGURATION
  // ============================================================================
  
  const CONFIG = {
    MIN_SUSPICIOUS_FRAME_SIZE: 400, // pixels
    SCAN_INTERVAL: 2000, // 2 seconds
    ENABLE_BLOB_BLOCKING: true,
    ENABLE_GAME_DETECTION: true
  };
  
  // ============================================================================
  // GAME ENGINE SIGNATURES
  // ============================================================================
  
  const GAME_ENGINE_SIGNATURES = [
    // Unity
    /UnityLoader\.js/i,
    /unityInstance/i,
    /\.unity3d/i,
    /UnityWebGL/i,
    
    // Construct 2/3
    /c2runtime\.js/i,
    /c3runtime\.js/i,
    /construct\.net/i,
    
    // Phaser
    /phaser\.js/i,
    /phaser\.min\.js/i,
    
    // Game engines
    /godot\.js/i,
    /pixi\.js/i,
    /three\.js.*game/i,
    
    // Common game frameworks
    /ruffle/i,
    /emulator/i,
    /\/rom\//i,
    /\.nes$/i,
    /\.gba$/i,
    /\.gb$/i,
    
    // Unblocked games indicators
    /unblocked/i,
    /unblocker/i,
    /game.*proxy/i,
    
    // Flash emulators
    /ruffle.*swf/i,
    /flashplayer/i
  ];
  
  // ============================================================================
  // BLOB URL DETECTION
  // ============================================================================
  
  function inspectBlobURL(iframe) {
    const src = iframe.src;
    
    if (!src || !src.startsWith('blob:')) {
      return false;
    }
    
    // Check frame size (games are typically large/fullscreen)
    const width = iframe.offsetWidth;
    const height = iframe.offsetHeight;
    
    if (width < CONFIG.MIN_SUSPICIOUS_FRAME_SIZE || 
        height < CONFIG.MIN_SUSPICIOUS_FRAME_SIZE) {
      return false; // Too small to be a game
    }
    
    console.warn('[GOOGLE SITES] Suspicious blob URL detected:', {
      src,
      width,
      height,
      parentURL: window.location.href
    });
    
    // Report violation
    chrome.runtime.sendMessage({
      type: 'SECURITY_VIOLATION',
      subType: 'BLOB_URL_DETECTED',
      url: window.location.href,
      details: {
        blobURL: src,
        frameWidth: width,
        frameHeight: height,
        suspectedContent: 'Embedded game or blocked content'
      }
    });
    
    // Block the iframe
    if (CONFIG.ENABLE_BLOB_BLOCKING) {
      iframe.src = 'about:blank';
      iframe.style.display = 'none';
      
      // Add blocking message
      const blockMessage = document.createElement('div');
      blockMessage.style.cssText = `
        padding: 20px;
        background: #f8d7da;
        border: 2px solid #721c24;
        border-radius: 8px;
        margin: 20px;
        font-family: Arial, sans-serif;
        color: #721c24;
      `;
      blockMessage.innerHTML = `
        <h3>🛡️ Content Blocked</h3>
        <p><strong>Reason:</strong> Blob URL embedding detected</p>
        <p>This technique is commonly used to bypass content filters by encoding blocked content within the page.</p>
        <p><small>Violation logged: ${new Date().toISOString()}</small></p>
      `;
      
      if (iframe.parentElement) {
        iframe.parentElement.insertBefore(blockMessage, iframe);
      }
    }
    
    return true;
  }
  
  // ============================================================================
  // GAME ENGINE DETECTION
  // ============================================================================
  
  async function inspectFrameContent(iframe) {
    // Try to access iframe content (only works for same-origin or when we have permissions)
    try {
      const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
      if (!iframeDoc) return false;
      
      const html = iframeDoc.documentElement.outerHTML;
      
      // Check for game engine signatures
      for (const signature of GAME_ENGINE_SIGNATURES) {
        if (signature.test(html)) {
          console.warn('[GOOGLE SITES] Game engine detected:', signature.toString());
          
          chrome.runtime.sendMessage({
            type: 'SECURITY_VIOLATION',
            subType: 'GAME_ENGINE_DETECTED',
            url: window.location.href,
            details: {
              signature: signature.toString(),
              iframeSrc: iframe.src,
              detection: 'Game engine signature found in iframe content'
            }
          });
          
          // Block the iframe
          if (CONFIG.ENABLE_GAME_DETECTION) {
            iframe.src = 'about:blank';
            iframe.style.display = 'none';
            
            const blockMessage = document.createElement('div');
            blockMessage.style.cssText = `
              padding: 20px;
              background: #fff3cd;
              border: 2px solid #856404;
              border-radius: 8px;
              margin: 20px;
              font-family: Arial, sans-serif;
              color: #856404;
            `;
            blockMessage.innerHTML = `
              <h3>🛡️ Game Content Blocked</h3>
              <p><strong>Reason:</strong> Game engine detected (${signature.toString().substring(0, 50)})</p>
              <p>Gaming content is not permitted during instructional time per district acceptable use policy.</p>
              <p><small>Violation logged: ${new Date().toISOString()}</small></p>
            `;
            
            if (iframe.parentElement) {
              iframe.parentElement.insertBefore(blockMessage, iframe);
            }
          }
          
          return true;
        }
      }
    } catch (error) {
      // Cross-origin frame - can't inspect content
      // This is expected for many iframes
      return false;
    }
    
    return false;
  }
  
  // ============================================================================
  // CLOUDFLARE WORKER DETECTION
  // ============================================================================
  
  function detectCloudflareWorkerProxy(iframe) {
    const src = iframe.src;
    
    if (!src) return false;
    
    // Check for Cloudflare Workers patterns
    const workerPatterns = [
      /\.workers\.dev/i,
      /\.pages\.dev/i,
      /cloudflare.*proxy/i
    ];
    
    for (const pattern of workerPatterns) {
      if (pattern.test(src)) {
        // Additional check: is this a generic subdomain?
        const url = new URL(src);
        const subdomain = url.hostname.split('.')[0];
        
        // Suspicious if subdomain looks random (e.g., abc123xyz)
        if (subdomain.length > 8 && /[a-z0-9]{8,}/.test(subdomain)) {
          console.warn('[GOOGLE SITES] Cloudflare Worker proxy suspected:', src);
          
          chrome.runtime.sendMessage({
            type: 'SECURITY_VIOLATION',
            subType: 'CLOUDFLARE_WORKER_PROXY',
            url: window.location.href,
            details: {
              iframeSrc: src,
              suspectedProxy: 'Cloudflare Worker used as content proxy'
            }
          });
          
          return true;
        }
      }
    }
    
    return false;
  }
  
  // ============================================================================
  // COMPREHENSIVE IFRAME SCANNER
  // ============================================================================
  
  function scanAllIframes() {
    const iframes = document.querySelectorAll('iframe');
    let violationsDetected = 0;
    
    iframes.forEach(iframe => {
      // Check blob URLs
      if (inspectBlobURL(iframe)) {
        violationsDetected++;
      }
      
      // Check for Cloudflare Workers
      if (detectCloudflareWorkerProxy(iframe)) {
        violationsDetected++;
      }
      
      // Check frame content for game engines
      inspectFrameContent(iframe);
    });
    
    if (violationsDetected > 0) {
      console.warn(`[GOOGLE SITES] Scan complete: ${violationsDetected} violations detected`);
    }
  }
  
  // ============================================================================
  // BASE64 ENCODED CONTENT DETECTION
  // ============================================================================
  
  function detectBase64Encoding() {
    // Look for extremely long data URIs or Base64 strings in scripts
    const scripts = document.querySelectorAll('script');
    
    scripts.forEach(script => {
      const content = script.textContent;
      
      // Look for very long Base64 strings (likely encoded games)
      const base64Pattern = /[A-Za-z0-9+/]{1000,}/g;
      const matches = content.match(base64Pattern);
      
      if (matches && matches.length > 0) {
        console.warn('[GOOGLE SITES] Long Base64 string detected - possible encoded content');
        
        // Check if it's being decoded and used
        if (/atob\s*\(/.test(content) && /createObjectURL/.test(content)) {
          chrome.runtime.sendMessage({
            type: 'SECURITY_VIOLATION',
            subType: 'BASE64_GAME_ENCODING',
            url: window.location.href,
            details: {
              technique: 'Base64 encoding with blob URL creation',
              stringLength: matches[0].length,
              suspectedContent: 'Encoded game or blocked content'
            }
          });
        }
      }
    });
  }
  
  // ============================================================================
  // INITIALIZATION
  // ============================================================================
  
  function initialize() {
    console.log('[GOOGLE SITES INSPECTOR] Initializing...');
    
    // Initial scan
    setTimeout(scanAllIframes, 1000);
    
    // Periodic scanning
    setInterval(scanAllIframes, CONFIG.SCAN_INTERVAL);
    
    // Check for Base64 encoding
    setTimeout(detectBase64Encoding, 2000);
    
    // Watch for dynamically added iframes
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeName === 'IFRAME') {
            // Scan new iframe after a short delay (let it load)
            setTimeout(() => {
              inspectBlobURL(node);
              detectCloudflareWorkerProxy(node);
              inspectFrameContent(node);
            }, 500);
          }
        });
      });
    });
    
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });
    }
    
    console.log('[GOOGLE SITES INSPECTOR] Active');
  }
  
  // Wait for page to be somewhat loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
  } else {
    initialize();
  }
  
})();
// Written by Jim Tyler, Microsoft MVP
// Visit my Github for project notes: https://github.com/jimrtyler/youshallnotpass