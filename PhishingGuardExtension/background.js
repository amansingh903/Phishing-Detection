chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only scan real websites (ignore chrome:// and chrome-extension:// URLs)
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        
        fetch('http://127.0.0.1:8000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "danger") {
                // 1. Trigger OS Notification (Requires icon.png in folder)
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icon.png', 
                    title: '🚨 Phishing Alert!',
                    message: `AI detected a malicious site with ${parseFloat(data.confidence).toFixed(1)}% confidence.`,
                    priority: 2,
                    requireInteraction: true 
                });

                // 2. Inject the red warning screen
                chrome.scripting.executeScript({
                    target: { tabId: tabId },
                    func: injectPhishingWarning,
                    args: [parseFloat(data.confidence).toFixed(2) + "%"]
                });
            }
        })
        .catch(err => console.log("Backend offline. Start main.py"));
    }
});

function injectPhishingWarning(conf) {
    const overlay = document.createElement('div');
    Object.assign(overlay.style, {
        position: 'fixed', top: '0', left: '0',
        width: '100vw', height: '100vh',
        background: 'linear-gradient(135deg, #1a0000 0%, #7d0000 100%)',
        zIndex: '2147483647', display: 'flex',
        justifyContent: 'center', alignItems: 'center',
        color: 'white', fontFamily: 'system-ui, sans-serif', textAlign: 'center'
    });

    overlay.innerHTML = `
        <div style="padding: 50px; background: rgba(0,0,0,0.3); border-radius: 30px; border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(15px); max-width: 500px;">
            <div style="font-size: 80px; margin-bottom: 20px;">🚨</div>
            <h1 style="font-size: 32px; color: #ff4d4d; margin: 0; font-weight: 900;">PHISHING DETECTED</h1>
            <p style="font-size: 18px; margin: 20px 0; opacity: 0.9;">AI is ${conf} sure this site is a malicious attempt to steal your data.</p>
            <button id="pg-leave-btn" style="background: #ff4d4d; color: white; border: none; padding: 18px 40px; border-radius: 12px; font-weight: bold; font-size: 18px; cursor: pointer;">Get Me Out of Here</button>
        </div>
    `;

    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    document.getElementById('pg-leave-btn').onclick = () => {
        window.location.href = "about:blank";
    };
}