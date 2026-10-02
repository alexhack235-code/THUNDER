// ==============================================================================
// THUNDER IP ROTATOR - High-Speed Multi-Endpoint Evaluator & Failover Engine
// Built by: NEXO-TECH
// ==============================================================================

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const poolPath = path.join(__dirname, 'api_pool.json');
const endpoints = JSON.parse(fs.readFileSync(poolPath, 'utf8'));

function fetchEndpoint(ep, timeoutMs = 3500) {
    return new Promise((resolve) => {
        const start = Date.now();
        const client = ep.url.startsWith('https') ? https : http;
        
        const req = client.get(ep.url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 THUNDER/1.0',
                'Accept': 'application/json, text/plain, */*'
            },
            timeout: timeoutMs
        }, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                const latency = Date.now() - start;
                let parsedIP = null;

                try {
                    if (ep.type === 'text') {
                        const match = data.trim().match(/([0-9a-fA-F:\.]+)/);
                        parsedIP = match ? match[1] : data.trim();
                    } else if (ep.type === 'json' && ep.key) {
                        const j = JSON.parse(data);
                        parsedIP = j[ep.key];
                    } else if (ep.type === 'trace') {
                        const line = data.split('\n').find(l => l.startsWith('ip='));
                        if (line) parsedIP = line.replace('ip=', '').trim();
                    } else if (ep.type === 'regex' && ep.regex) {
                        const r = new RegExp(ep.regex);
                        const match = data.match(r);
                        if (match) parsedIP = match[1];
                    }
                } catch (e) {}

                if (parsedIP && (parsedIP.includes('.') || parsedIP.includes(':'))) {
                    resolve({
                        id: ep.id,
                        name: ep.name,
                        url: ep.url,
                        ip: parsedIP,
                        latencyMs: latency,
                        status: 'HEALTHY'
                    });
                } else {
                    resolve({ id: ep.id, name: ep.name, url: ep.url, status: 'FAILED', error: 'Invalid response format' });
                }
            });
        });

        req.on('error', (err) => {
            resolve({ id: ep.id, name: ep.name, url: ep.url, status: 'UNREACHABLE', error: err.message });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ id: ep.id, name: ep.name, url: ep.url, status: 'TIMEOUT', error: 'Request timed out' });
        });
    });
}

async function benchmarkAll(sampleSize = 25) {
    console.log(`\n===============================================================`);
    console.log(`⚡ THUNDER MULTI-ENDPOINT POOL EVALUATION (NEXO-TECH) ⚡`);
    console.log(`===============================================================`);
    console.log(`[+] Total Endpoints in Pool : ${endpoints.length}`);
    console.log(`[+] Benchmarking Sample Size: ${sampleSize} concurrent streams...\n`);

    // Shuffle and pick sample
    const shuffled = [...endpoints].sort(() => 0.5 - Math.random());
    const subset = shuffled.slice(0, sampleSize);

    const results = await Promise.all(subset.map(ep => fetchEndpoint(ep)));
    const healthy = results.filter(r => r.status === 'HEALTHY').sort((a, b) => a.latencyMs - b.latencyMs);

    console.log(`[+] Live Healthy Endpoints : ${healthy.length} / ${subset.length}`);
    if (healthy.length > 0) {
        console.log(`[+] Current Public IP      : \x1b[32m\x1b[1m${healthy[0].ip}\x1b[0m`);
        console.log(`[+] Fastest Endpoint Node  : ${healthy[0].name} (${healthy[0].latencyMs} ms)\n`);

        console.log(`--- TOP 10 FASTEST LIVE ENDPOINTS ---`);
        healthy.slice(0, 10).forEach((h, idx) => {
            console.log(`${idx + 1}. [${h.latencyMs}ms] ${h.name.padEnd(25)} -> ${h.url}`);
        });
    } else {
        console.log(`[-] Could not contact endpoints. Check internet connection.`);
    }

    return healthy;
}

// Check command-line arguments
const args = process.argv.slice(2);
const limit = args[0] ? parseInt(args[0], 10) : 20;

benchmarkAll(limit);
