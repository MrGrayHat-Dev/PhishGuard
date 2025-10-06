// content_script.js (updated)

/**
 * Shows a warning banner at the top of the page.
 * @param {string} verdict - 'malicious', 'suspicious', or 'safe'.
 * @param {number} score - The numeric score from the backend.
 */
function showWarning(verdict, score) {
    // Remove any existing banner first
    const existingBanner = document.getElementById('phish-guard-banner');
    if (existingBanner) existingBanner.remove();

    if (!verdict || verdict === 'safe') {
        console.log('Phish Guard: Email seems safe.');
        return;
    }

    const banner = document.createElement('div');
    banner.id = 'phish-guard-banner';
    let bannerText = '';
    let bannerColor = '';

    switch (verdict) {
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
    Object.assign(banner.style, {
        position: 'fixed',
        top: '0',
        left: '0',
        width: '100%',
        padding: '12px',
        backgroundColor: bannerColor,
        color: 'black',
        textAlign: 'center',
        zIndex: '99999',
        fontSize: '16px',
        fontWeight: 'bold',
        borderBottom: '2px solid black'
    });

    document.body.appendChild(banner);

    // Allow user to dismiss the banner
    banner.onclick = () => banner.remove();
}

/**
 * Extracts email content and sends it for scanning.
 * This function uses heuristics and may need adjustment for different webmail clients.
 */
function scanVisibleEmail() {
    // Heuristic selectors for Gmail. These WILL need to be adapted for Outlook etc.
    const emailBodyNode = document.querySelector('.adn.ads'); // A common Gmail body container
    const headersNode = document.querySelector('.ajv'); // "Show details" container in Gmail

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
// This is more reliable than timers for single-page apps like Gmail.
const observer = new MutationObserver((mutations) => {
    // A simple check to see if the DOM has changed significantly
    for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
            // Use a small delay to ensure the email content is fully rendered
            setTimeout(scanVisibleEmail, 500);
            return;
        }
    }
});

// Start observing the main part of the page where emails are loaded.
const targetNode = document.body;
if (targetNode) {
    observer.observe(targetNode, { childList: true, subtree: true });
}