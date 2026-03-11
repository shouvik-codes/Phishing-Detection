const express = require('express');
const cors = require('cors');
const validator = require('validator'); // Library for string validation
const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

/**
 * Advanced Phishing Detection Logic
 */
const analyzeURL = (inputUrl) => {
    try {
        const urlObj = new URL(inputUrl);
        const hostname = urlObj.hostname.toLowerCase();
        const protocol = urlObj.protocol;

        // 1. Check for IP-based URLs 
        if (validator.isIP(hostname)) return { isPhishing: true, reason: "IP-based URLs are highly suspicious." };

        // 2. Check for Non-HTTPS 
        if (protocol !== 'https:') return { isPhishing: true, reason: "Insecure protocol (HTTP) detected." };

        // 3. Detect "Typosquatting" and Look-alike characters
        // Flags zeros used as 'o', or '1' used as 'l'
        const suspiciousChars = ['0', '1', '@', '!', '$'];
        if (suspiciousChars.some(char => hostname.includes(char))) {
            return { isPhishing: true, reason: "URL contains suspicious characters or symbols." };
        }

        // 4. Check for excessive subdomains 
        const dotCount = (hostname.match(/\./g) || []).length;
        if (dotCount > 3) return { isPhishing: true, reason: "Too many subdomains detected." };

        // 5. Deep Keyword Analysis 
        const threatKeywords = ['login', 'verify', 'update', 'banking', 'secure-account', 'signin', 'wp-admin'];
        if (threatKeywords.some(key => hostname.includes(key) || urlObj.pathname.includes(key))) {
            return { isPhishing: true, reason: "URL contains sensitive keywords used in fraud." };
        }

        // 6. Dangerous TLDs (Top Level Domains)
        const riskyTLDs = ['.xyz', '.top', '.zip', '.icu', '.work', '.click'];
        if (riskyTLDs.some(tld => hostname.endsWith(tld))) {
            return { isPhishing: true, reason: "This site uses a high-risk domain extension." };
        }

        return { isPhishing: false, reason: "No immediate threats found." };
    } catch (e) {
        return { isPhishing: true, reason: "Invalid URL format." };
    }
};

app.post('/verify', (req, res) => {
    const { url } = req.body;
    
    if (!url) return res.status(400).json({ error: "URL is required" });

    const result = analyzeURL(url);

    setTimeout(() => {
        res.json({
            isPhishing: result.isPhishing,
            reason: result.reason,
            timestamp: new Date().toISOString()
        });
    }, 1000); // Artificial delay for "Machine Learning" feel
});

app.listen(PORT, () => console.log(`🚀 Advanced Shield running on port ${PORT}`));