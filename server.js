const express = require('express');
const cors = require('cors');
const validator = require('validator'); // Library for string validation
const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

/**
 * Phishing Detection Logic
 */
const analyzeURL = (inputUrl) => {
    try {
        const urlObj = new URL(inputUrl);
        const hostname = urlObj.hostname.toLowerCase();
        const protocol = urlObj.protocol;
        
        // 1. Calculate URL length inside the function scope
        // Legitimate URLs are typically < 54 characters.
        const urlLength = inputUrl.length;

        // 2. Check for IP-based URLs 
        if (validator.isIP(hostname)) return { isPhishing: true, reason: "IP-based URLs are highly suspicious." };

        // 3. Check for Non-HTTPS 
        if (protocol !== 'https:') return { isPhishing: true, reason: "Insecure protocol (HTTP) detected." };

        // 4. URL Length and Subdomain Logic
        // Attackers use long URLs to hide the real domain on mobile devices.
        if (urlLength >= 75) {
            return { 
                isPhishing: true, 
                reason: `Extreme URL length detected (${urlLength} characters). This is a common tactic to hide the real domain name.` 
            };
        } else if (urlLength >= 54) {
            // Check for excessive subdomains if length is suspicious
            const dotCount = (hostname.match(/\./g) || []).length;
            if (dotCount > 2) {
                return { 
                    isPhishing: true, 
                    reason: "Suspiciously long URL combined with multiple subdomains detected." 
                };
            }
        }

        // 5. Detect Tunneling Services (trycloudflare, ngrok, etc.)
        const tunnelingServices = ['trycloudflare.com', 'loca.lt', 'ngrok-free.app'];
        if (tunnelingServices.some(service => hostname.endsWith(service))) {
            return { isPhishing: true, reason: "Temporary tunnel detected. These are frequently used to host hidden phishing sites." };
        }

        // 6. Detect "Typosquatting" and Look-alike characters
        const suspiciousChars = ['0', '1', '@', '!', '$'];
        if (suspiciousChars.some(char => hostname.includes(char))) {
            return { isPhishing: true, reason: "URL contains suspicious characters or symbols." };
        }

        // 7. Deep Keyword Analysis 
        const threatKeywords = ['login', 'verify', 'update', 'banking', 'secure-account', 'signin', 'wp-admin'];
        if (threatKeywords.some(key => hostname.includes(key) || urlObj.pathname.includes(key))) {
            return { isPhishing: true, reason: "URL contains sensitive keywords used in fraud." };
        }

        // 8. Dangerous TLDs (Top Level Domains)
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
