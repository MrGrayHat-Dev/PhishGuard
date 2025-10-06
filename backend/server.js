require('dotenv').config();
const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const cors = require('cors');
const NodeCache = require('node-cache');
const dns = require('dns').promises;
const fs = require('fs').promises;
const path = require('path');

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// CONFIG
const PORT = process.env.PORT || 8080;
const IPQS_API_KEY = process.env.IPQS_API_KEY || null;
const PHISHTANK_API_KEY = process.env.PHISHTANK_API_KEY || null;
const STALKPHISH_API_KEY = process.env.STALKPHISH_API_KEY || null;

const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL) || 60 * 60; // 1h
const MALICIOUS_THRESHOLD = 80;
const SUSPICIOUS_THRESHOLD = 50;

const cache = new NodeCache({ stdTTL: CACHE_TTL_SECONDS, checkperiod: 120 });

// SECTION 1: ORIGINAL UTILITY FUNCTIONS (Needed for Link Scanning)

function normalizeScore(n) {
    if (n == null || Number.isNaN(n)) return null;
    return Math.max(0, Math.min(100, Math.round(Number(n))));
}

function isPunycode(hostname) {
    return hostname.includes('xn--');
}

const WEIGHTS = {
    ipqs: 0.5,
    stalkphish: 0.25,
    heuristics: 15
};

function hasIPInHostname(urlObj) {
    const host = urlObj.hostname;
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

const suspiciousTLDs = new Set(['zip', 'review', 'country', 'kim', 'gq', 'work', 'top', 'men', 'party']);

function heuristicsScore({ url, anchorText, redirectCount, finalUrl }) {
    try {
        const urlObj = new URL(url);
        let score = 0;
        if (anchorText) {
            const m = anchorText.match(/https?:\/\/[^\s/]+|www\.[^\s/]+|[a-z0-9.-]+\.[a-z]{2,}/i);
            if (m) {
                try {
                    const aHost = m[0].startsWith('http') ? new URL(m[0]).hostname : m[0].replace(/^www\./i, '');
                    if (aHost && aHost !== urlObj.hostname) score += 12;
                } catch (e) {}
            }
        }
        if (isPunycode(urlObj.hostname)) score += 10;
        if (hasIPInHostname(urlObj)) score += 12;
        const tld = urlObj.hostname.split('.').pop()?.toLowerCase();
        if (tld && suspiciousTLDs.has(tld)) score += 8;
        if (typeof redirectCount === 'number' && redirectCount >= 3) score += Math.min(12, redirectCount * 3);
        if (finalUrl) {
            try {
                const f = new URL(finalUrl);
                if (f.hostname !== urlObj.hostname) score += 6;
            } catch (e) {}
        }
        return score;
    } catch (e) {
        return 0;
    }
}

async function checkDomainAuth(domain) {
    const result = { spf: false, dmarc: false };
    try {
        const txts = await dns.resolveTxt(domain);
        result.spf = txts.some(rec => rec.join('').toLowerCase().startsWith('v=spf1'));
    } catch (e) {}
    try {
        const dmarcName = `_dmarc.${domain}`;
        const txts2 = await dns.resolveTxt(dmarcName);
        result.dmarc = txts2.some(rec => rec.join('').toLowerCase().startsWith('v=dmarc1'));
    } catch (e) {}
    return result;
}

async function callIPQS(url) {
    if (!IPQS_API_KEY) return null;
    try {
        const endpoint = `https://ipqualityscore.com/api/json/url/${IPQS_API_KEY}/${encodeURIComponent(url)}`;
        const r = await axios.get(endpoint, { timeout: 15000 });
        const data = r.data;
        return {
            raw: data,
            score: typeof data.fraud_score !== 'undefined' ? normalizeScore(data.fraud_score) : null,
            flags: { malicious: !!data.malicious, phishing: !!data.phishing, malware: !!data.malware, suspicious: !!data.suspicious }
        };
    } catch (err) {
        return null;
    }
}

async function callStalkPhish(url) {
    if (!STALKPHISH_API_KEY) return null;
    try {
        const endpoint = `https://api.stalkphish.io/v1/scan?key=${STALKPHISH_API_KEY}&url=${encodeURIComponent(url)}`;
        const r = await axios.get(endpoint, { timeout: 15000 });
        const data = r.data;
        return {
            raw: data,
            score: data && typeof data.riskScore !== 'undefined' ? normalizeScore(data.riskScore) : null
        };
    } catch (err) {
        return null;
    }
}

async function getRedirectInfo(url) {
    try {
        const r = await axios.get(url, { timeout: 10000, maxRedirects: 10, validateStatus: null });
        const finalUrl = r.request?.res?.responseUrl || r.request?.path || null;
        const redirectCount = r.request?._redirectable?._redirectCount || 0;
        return { finalUrl, redirectCount };
    } catch (err) {
        return { finalUrl: null, redirectCount: 0 };
    }
}


async function aggregateSignals({ url, anchorText, senderDomain }) {
    const cacheKey = `scan::${url}::${anchorText || ''}::${senderDomain || ''}`;
    const cached = cache.get(cacheKey);
    if (cached) return { ...cached, cached: true };

    const [ipqsR, stalkR, redirectR, authR] = await Promise.all([
        callIPQS(url),
        callStalkPhish(url),
        getRedirectInfo(url),
        senderDomain ? checkDomainAuth(senderDomain) : Promise.resolve({ spf: false, dmarc: false })
    ]);

    const ipqsScore = ipqsR?.score ?? null;
    const stalkScore = stalkR?.score ?? null;
    const heurScoreRaw = heuristicsScore({ url, anchorText, redirectCount: redirectR?.redirectCount, finalUrl: redirectR?.finalUrl });

    let weightedSum = 0;
    let totalWeight = 0;
    if (ipqsScore !== null) { weightedSum += ipqsScore * WEIGHTS.ipqs; totalWeight += WEIGHTS.ipqs; }
    if (stalkScore !== null) { weightedSum += stalkScore * WEIGHTS.stalkphish; totalWeight += WEIGHTS.stalkphish; }

    let baseScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 50;
    const heuristicsContribution = Math.min(30, heurScoreRaw);
    const authBonus = (authR.spf ? -6 : 6) + (authR.dmarc ? -4 : 4);
    const finalRaw = Math.max(0, Math.min(100, baseScore + heuristicsContribution + authBonus));

    const explicitMalicious = ipqsR?.flags?.malicious || ipqsR?.flags?.phishing;
    const finalScore = explicitMalicious ? Math.max(finalRaw, 85) : finalRaw;

    let verdict = 'safe';
    if (finalScore >= 70) verdict = 'malicious';
    else if (finalScore >= 40) verdict = 'suspicious';

    const result = { url, verdict, score: finalScore, breakdown: { /*...*/ } };
    cache.set(cacheKey, result);
    return result;
}



// SECTION 2: NEW EMAIL ANALYSIS FUNCTIONS 

function analyzeHeaders(headersText) {
    let score = 0;
    const report = { spf: 'neutral', dkim: 'neutral', dmarc: 'neutral', mismatch_from_return: false };
    if (!headersText) return { score: 10, report };

    const lowerHeaders = headersText.toLowerCase();
    if (lowerHeaders.includes('spf=pass')) { score -= 15; report.spf = 'pass'; }
    else if (lowerHeaders.includes('spf=fail')) { score += 25; report.spf = 'fail'; }
    if (lowerHeaders.includes('dkim=pass')) { score -= 10; report.dkim = 'pass'; }
    else if (lowerHeaders.includes('dkim=fail')) { score += 20; report.dkim = 'fail'; }
    if (lowerHeaders.includes('dmarc=pass')) { score -= 5; report.dmarc = 'pass'; }
    else if (lowerHeaders.includes('dmarc=fail')) { score += 25; report.dmarc = 'fail'; }
    
    const fromMatch = lowerHeaders.match(/from:.*<([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})>/);
    const returnPathMatch = lowerHeaders.match(/return-path:.*<([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})>/);
    if (fromMatch && returnPathMatch && fromMatch[1] !== returnPathMatch[1]) {
        score += 20; report.mismatch_from_return = true;
    }
    return { score: Math.max(0, score), report };
}

function analyzeBody(bodyText) {
    let score = 0;
    const keywordsFound = [];
    if (!bodyText) return { score, keywordsFound };
    const urgencyKeywords = ['urgent', 'action required', 'account suspended', 'verify your account', 'password expired', 'unusual activity', 'security alert', 'confirm your identity'];
    const lowerBody = bodyText.toLowerCase();
    for (const keyword of urgencyKeywords) {
        if (lowerBody.includes(keyword)) {
            score += 8;
            keywordsFound.push(keyword);
        }
    }
    return { score, keywordsFound };
}

// SECTION 3: API ENDPOINTS

app.post('/scan-email', async (req, res) => {
    try {
        const { headers, body, links } = req.body || {};
        if (!body) return res.status(400).json({ error: 'missing email body' });

        const headerAnalysis = analyzeHeaders(headers);
        const bodyAnalysis = analyzeBody(body);
        
        const linkScanPromises = (links || []).map(link => aggregateSignals({ url: link.href, anchorText: link.anchorText }));
        const linkResults = await Promise.all(linkScanPromises);

        let highestLinkScore = 0;
        let mostMaliciousLink = null;
        for (const result of linkResults) {
            if (result && result.score > highestLinkScore) {
                highestLinkScore = result.score;
                mostMaliciousLink = { url: result.url, score: result.score };
            }
        }
        
        let finalScore = (headerAnalysis.score * 0.4) + (bodyAnalysis.score * 0.2) + (highestLinkScore * 0.4);
        const normalizedScore = Math.round(Math.min(100, finalScore));

        let verdict = 'safe';
        if (normalizedScore >= MALICIOUS_THRESHOLD) verdict = 'malicious';
        else if (normalizedScore >= SUSPICIOUS_THRESHOLD) verdict = 'suspicious';
        
        const breakdown = {
            headerAnalysis: headerAnalysis.report,
            bodyAnalysis: { keywords: bodyAnalysis.keywordsFound },
            linkAnalysis: { highestLinkScore, mostMaliciousLink },
            finalScore: normalizedScore
        };

        return res.json({ ok: true, verdict, score: normalizedScore, breakdown });

    } catch (err) {
        console.error('scan-email error', err);
        return res.status(500).json({ ok: false, error: 'email_scan_failed' });
    }
});

app.post('/scan', async (req, res) => {
    try {
        const { url, anchorText, senderDomain } = req.body || {};
        if (!url) return res.status(400).json({ error: 'missing url' });
        const aggregated = await aggregateSignals({ url, anchorText, senderDomain });
        return res.json({ ok: true, ...aggregated });
    } catch (err) {
        return res.status(500).json({ ok: false, error: 'scan_failed' });
    }
});

app.post('/feedback', async (req, res) => {
    try {
        const { url, verdict, comment } = req.body || {};
        if (!url || !verdict) return res.status(400).json({ error: 'missing url or verdict' });
        const feedbackPath = path.join(__dirname, 'feedback.json');
        const entry = { ts: new Date().toISOString(), url, verdict, comment: comment || '' };
        await fs.appendFile(feedbackPath, JSON.stringify(entry) + '\n', 'utf8');
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ ok: false, error: 'feedback_failed' });
    }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Phish scanner backend running on ${PORT}`));