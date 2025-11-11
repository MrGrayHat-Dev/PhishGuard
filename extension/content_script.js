
/* Shows a warning banner at the top of the page.
* @param {string} verdict - 'malicious', 'suspicious', or 'safe'.
* @param {number} score - The numeric score from the backend.
*/
function showWarning(verdict, score) {
    // Remove any existing banner first
    const existingBanner = document.getElementById('phish-guard-banner');
    if (existingBanner) existingBanner.remove();

    if (!verdict) {
        console.log('Phish Guard: No verdict received.');
        return;
    }

    const banner = document.createElement('div');
    banner.id = 'phish-guard-banner';
    let bannerText = '';
    let bannerColor = '';

    switch (verdict) {
        case 'safe':
            bannerText = `✅ SAFE: This email appears to be safe. Score: ${score}/100`;
            bannerColor = '#28a745';
            break;
        case 'malicious':
            bannerText = `🚨 DANGER: This email is likely a phishing attempt. Score: ${score}/100`;
            bannerColor = '#ff4d4d';
            break;
        case 'suspicious':
            bannerText = `⚠️ CAUTION: This email contains suspicious elements. Score: ${score}/100`;
            bannerColor = '#ffc107';
            break;
    }

    banner.textContent = bannerText;
    // This is the NEW pop-up style
    Object.assign(banner.style, {
        position: 'fixed',
        top: '20px',
        left: '50%',
        transform: 'translateX(-50%)',
        width: '350px',
        padding: '16px',
        backgroundColor: bannerColor,
        color: 'black',
        textAlign: 'center',
        zIndex: '99999',
        fontSize: '16px',
        fontWeight: 'bold',
        borderRadius: '8px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.15)'
    });

    document.body.appendChild(banner);

    setTimeout(() => {
        banner.remove();
    }, 3000);
    // Allow user to dismiss the banner
    banner.onclick = () => banner.remove();
}

/**
 * Extracts email content and sends it for scanning.
 * This function uses heuristics and may need adjustment for different webmail clients.
 */
function scanVisibleEmail() {
    const emailBodyNode = document.querySelector('.adn.ads');
    const headersNode = document.querySelector("pre");


    if (!emailBodyNode || emailBodyNode.dataset.phishGuardScanned) {
        return; // Either not an email view or already scanned
    }

    emailBodyNode.dataset.phishGuardScanned = 'true'; // Mark as scanned to prevent re-scans

    const body = emailBodyNode.innerText; // Use innerText to get clean text for body analysis
    const headers = headersNode ? headersNode.innerText : '';

    const links = Array.from(emailBodyNode.querySelectorAll('a')).map(link => ({
        href: link.href,
        anchorText: (link.textContent || '').trim()
    }));

    console.log('Phish Guard: Scanning email...');
    chrome.runtime.sendMessage({
        type: 'scan_email',
        data: { headers, body, links }
    }, (resp) => {
        if (resp && resp.ok && resp.data) {
            console.log('Phish Guard Scan Result:', resp.data);
            showWarning(resp.data.verdict, resp.data.score);
        } else {
            console.error('Phish Guard: Scan failed.', resp?.error);
        }
    });
}

// Use a MutationObserver to detect when a new email is loaded in the DOM.
const observer = new MutationObserver((mutations) => {
    // A simple check to see if the DOM has changed significantly
    for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
            // Use a small delay to ensure the email content is fully rendered
            setTimeout(scanVisibleEmail, 200);
            return;
        }
    }
});

// Start observing the main part of the page where emails are loaded.
const targetNode = document.body;
if (targetNode) {
    observer.observe(targetNode, { childList: true, subtree: true });
}