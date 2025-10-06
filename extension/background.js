chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'scan_url') {
        chrome.storage.local.get(['backendUrl']).then(data => {
            const backendUrl = data.backendUrl || 'http://localhost:8080/scan';
            fetch(backendUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: msg.url,
                    anchorText: msg.anchorText,
                    senderDomain: msg.senderDomain
                })
            })
            .then(r => r.json())
            .then(json => sendResponse({ ok: true, data: json }))
            .catch(err => sendResponse({ ok: false, error: err.message }));
        }).catch(err => sendResponse({ ok: false, error: err.message }));
        return true; // keep channel open for async response
    }

    // NEW: Handler for the full email scan
    if (msg.type === 'scan_email') {
        chrome.storage.local.get(['backendUrl']).then(data => {
            // Assumes your backend URL in popup ends with /scan, so we replace it with /scan-email
            const baseUrl = (data.backendUrl || 'http://localhost:8080/scan').replace('/scan', '');
            fetch(`${baseUrl}/scan-email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(msg.data)
            })
            .then(r => r.json())
            .then(json => sendResponse({ ok: true, data: json }))
            .catch(err => sendResponse({ ok: false, error: err.message }));
        }).catch(err => sendResponse({ ok: false, error: err.message }));
        return true; // keep channel open for async response
    }
});