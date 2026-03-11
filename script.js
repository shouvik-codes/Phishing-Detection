document.addEventListener('DOMContentLoaded', () => {
    const verifyForm = document.getElementById('verifyForm');
    const resultBox = document.getElementById('resultMessage');

    verifyForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('urlInput').value;

        // UI Reset
        resultBox.style.display = "block";
        resultBox.innerHTML = "🔍 Running heuristic analysis...";
        resultBox.style.background = "rgba(255, 255, 255, 0.1)";

        try {
            const response = await fetch('http://localhost:3000/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlInput })
            });

            const data = await response.json();

            if (data.isPhishing) {
                resultBox.style.background = "#e74c3c"; // Red
                resultBox.innerHTML = `<strong>🚨 THREAT DETECTED</strong><br><small>${data.reason}</small>`;
            } else {
                resultBox.style.background = "#57b87c"; // Green
                resultBox.innerHTML = `<strong>✅ URL APPEARS SAFE</strong><br><small>${data.reason}</small>`;
            }
        } catch (err) {
            resultBox.style.background = "#f39c12";
            resultBox.textContent = "Offline: Start the server (node server.js)";
        }
    });
});