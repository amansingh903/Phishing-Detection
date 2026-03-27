document.addEventListener('DOMContentLoaded', async function() {
    const statusIcon = document.getElementById('status-icon');
    const statusMain = document.getElementById('status-main');
    const urlDisplay = document.getElementById('url-display');
    const confidenceBar = document.getElementById('confidence-bar');
    const labelDisplay = document.getElementById('label-display');
    const actionButton = document.getElementById('action-button');
    const body = document.body;

    try {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url) return;
        
        const currentUrl = tab.url;
        urlDisplay.innerText = currentUrl.length > 35 ? currentUrl.substring(0, 32) + "..." : currentUrl;

        const response = await fetch('http://127.0.0.1:8000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        });

        if (!response.ok) throw new Error("Server Error");

        const data = await response.json();

        body.classList.remove('loading');
        const cleanConf = parseFloat(data.confidence).toFixed(2) + "%";
        confidenceBar.style.width = cleanConf;

        if (data.status === "danger") {
            body.classList.add('dangerous');
            statusIcon.innerText = "🚨";
            statusMain.innerText = "Phishing Detected!";
            labelDisplay.innerText = `Threat Score: ${cleanConf}`;
            actionButton.innerText = "Close Dangerous Tab";
            actionButton.onclick = () => chrome.tabs.remove(tab.id);
        } else {
            body.classList.add('safe');
            statusIcon.innerText = "✅";
            statusMain.innerText = "Website is Safe";
            labelDisplay.innerText = `Security Score: ${cleanConf}`;
            actionButton.innerText = "Continue Browsing";
            actionButton.onclick = () => window.close();
        }

    } catch (error) {
        console.error("Connection Error:", error);
        statusMain.innerText = "Server Offline";
        statusIcon.innerText = "🔌";
        labelDisplay.innerText = "Start main.py in terminal";
        actionButton.innerText = "Retry Connection";
        actionButton.style.background = "#747d8c";
        actionButton.onclick = () => location.reload();
    }
});