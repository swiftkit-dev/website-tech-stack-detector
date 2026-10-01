import { Actor, log } from 'apify';
import { Resolver } from 'node:dns/promises';
import tls from 'node:tls';
import { analyze, TECH_COUNT, JS_CHAINS } from './analyzer.js';

await Actor.init();

const input = (await Actor.getInput()) || {};
const {
    websites = [],
    includeDetails = true,
    checkDns = true,
    respectRobotsTxt = true,
    maxConcurrency = 10,
    deepScan = false,
} = input;

const UA = 'Mozilla/5.0 (compatible; SwiftKit-TechStack/1.0; +https://apify.com/swiftkit)';

const list = [...new Set(websites.map((w) => String(w).trim()).filter(Boolean))];
if (!list.length) await Actor.fail('Add at least one website in "websites", e.g. stripe.com or https://www.notion.so');

function normalize(input) {
    const withProto = /^https?:\/\//i.test(input) ? input : `https://${input}`;
    return new URL(withProto);
}

async function robotsAllows(origin) {
    try {
        const res = await fetch(`${origin}/robots.txt`, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(10000) });
        if (!res.ok) return { allowed: true, robots: '' };
        const txt = (await res.text()).slice(0, 200000);
        // Minimal check: a "Disallow: /" for all agents (or ours) means the owner asks bots to stay out.
        let applies = false;
        let blocked = false;
        for (const line of txt.split(/\r?\n/)) {
            const l = line.replace(/#.*/, '').trim();
            const m = l.match(/^(user-agent|disallow)\s*:\s*(.*)$/i);
            if (!m) continue;
            if (m[1].toLowerCase() === 'user-agent') applies = m[2] === '*' || /swiftkit/i.test(m[2]);
            else if (applies && m[2].trim() === '/') blocked = true;
        }
        return { allowed: !blocked, robots: txt };
    } catch {
        return { allowed: true, robots: '' };
    }
}

// Public resolvers: consistent answers no matter where the Actor runs.
const dns = new Resolver({ timeout: 5000, tries: 2 });
dns.setServers(['1.1.1.1', '8.8.8.8']);

async function dnsInfo(host) {
    const root = host.replace(/^www\./, '');
    const safe = (p) => p.catch(() => []);
    const [mx, txt, ns] = await Promise.all([
        safe(dns.resolveMx(root)).then((r) => r.map((x) => x.exchange)),
        safe(dns.resolveTxt(root)).then((r) => r.map((x) => x.join(''))),
        safe(dns.resolveNs(root)),
    ]);
    const cname = await safe(dns.resolveCname(host));
    return { mx, txt, ns, cname };
}

function certIssuer(host) {
    return new Promise((resolve) => {
        const sock = tls.connect({ host, port: 443, servername: host, timeout: 8000 }, () => {
            const c = sock.getPeerCertificate();
            sock.end();
            resolve(c?.issuer ? [c.issuer.O, c.issuer.CN].filter(Boolean).join(' ') : '');
        });
        sock.on('error', () => resolve(''));
        sock.on('timeout', () => { sock.destroy(); resolve(''); });
    });
}

// Deep scan: load the page in headless Chrome to see what only appears after JavaScript runs.
let browserPromise = null;
function getBrowser() {
    if (!browserPromise) browserPromise = import('playwright').then(({ chromium }) => chromium.launch({ headless: true, args: ['--disable-dev-shm-usage'] }));
    return browserPromise;
}
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 SwiftKit-TechStack/1.0';

async function browserScan(href) {
    const browser = await getBrowser();
    const context = await browser.newContext({ userAgent: BROWSER_UA, locale: 'en-US', viewport: { width: 1366, height: 900 } });
    const requests = [];
    try {
        const page = await context.newPage();
        // Skip heavy files we don't need: faster and cheaper.
        await page.route('**/*', (route) => (['image', 'media', 'font'].includes(route.request().resourceType()) ? route.abort() : route.continue()));
        page.on('request', (r) => { if (requests.length < 800) requests.push(r.url()); });
        const resp = await page.goto(href, { waitUntil: 'domcontentloaded', timeout: 30000 });
        await page.waitForLoadState('load', { timeout: 12000 }).catch(() => {});
        await page.waitForTimeout(2500);
        const html = (await page.content()).slice(0, 3_000_000);
        const js = await page.evaluate((chains) => {
            const out = {};
            for (const chain of chains) {
                try {
                    let v = window;
                    for (const part of chain.split('.')) { if (v === undefined || v === null) break; v = v[part]; }
                    if (v === undefined || v === null || v === false) continue;
                    out[chain] = typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? String(v).slice(0, 200) : '';
                } catch { /* property getter threw */ }
            }
            return out;
        }, JS_CHAINS);
        const cookies = {};
        for (const c of await context.cookies()) cookies[c.name] = c.value;
        return { ok: true, status: resp?.status() ?? 0, finalUrl: page.url(), html, js, cookies, requests, headers: resp ? await resp.allHeaders() : {} };
    } catch (err) {
        return { ok: false, error: err.message.split('\n')[0] };
    } finally {
        await context.close().catch(() => {});
    }
}

async function inspect(site) {
    let url;
    try { url = normalize(site); } catch { return { input: site, status: 'invalid_url' }; }

    const { allowed, robots } = respectRobotsTxt ? await robotsAllows(url.origin) : { allowed: true, robots: '' };
    if (!allowed) return { input: site, url: url.href, status: 'blocked_by_robots_txt' };

    let res;
    try {
        res = await fetch(url.href, {
            headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml', 'Accept-Language': 'en' },
            redirect: 'follow',
            signal: AbortSignal.timeout(30000),
        });
    } catch (err) {
        if (!deepScan) return { input: site, url: url.href, status: 'unreachable', error: err.cause?.code || err.message };
        res = null;
    }
    let html = res ? (await res.text()).slice(0, 3_000_000) : '';
    const headers = {};
    res?.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let cookies = {};
    for (const c of res?.headers.getSetCookie?.() || []) {
        const [pair] = c.split(';');
        const i = pair.indexOf('=');
        if (i > 0) cookies[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
    }
    let httpStatus = res?.status ?? 0;
    let finalHref = res?.url || url.href;
    let jsValues = null;
    let requests = null;
    if (deepScan) {
        const b = await browserScan(url.href);
        if (!b.ok && !res) return { input: site, url: url.href, status: 'unreachable', error: b.error };
        if (b.ok) {
            html = b.html || html;
            cookies = { ...cookies, ...b.cookies };
            for (const [k, v] of Object.entries(b.headers || {})) if (headers[k] === undefined) headers[k] = v;
            jsValues = b.js;
            requests = b.requests;
            // The browser often gets through where a plain request was refused.
            if (b.status) httpStatus = b.status;
            finalHref = b.finalUrl || finalHref;
        }
    }
    const finalUrl = new URL(finalHref);
    const [dnsRec, issuer] = checkDns
        ? await Promise.all([dnsInfo(finalUrl.hostname), finalUrl.protocol === 'https:' ? certIssuer(finalUrl.hostname) : ''])
        : [{}, ''];

    const techs = analyze({ url: finalHref, html, headers, cookies, robots, dns: dnsRec, certIssuer: issuer, js: jsValues, requests });
    const byCategory = {};
    for (const t of techs) for (const c of t.categories) (byCategory[c] ||= []).push(t.name);

    const $title = html.match(/<title[^>]*>([^<]*)<\/title>/i);
    return {
        input: site,
        url: url.href,
        finalUrl: finalHref,
        domain: finalUrl.hostname.replace(/^www\./, ''),
        status: httpStatus >= 200 && httpStatus < 400 ? 'ok' : `http_${httpStatus}`,
        httpStatus,
        scanMode: deepScan ? 'deep' : 'fast',
        pageTitle: $title ? $title[1].trim().slice(0, 200) : null,
        technologyCount: techs.length,
        technologies: techs.map((t) => t.name),
        byCategory,
        details: includeDetails ? techs : undefined,
        emailProvider: guessEmail(dnsRec?.mx || []),
        scannedAt: new Date().toISOString(),
    };
}

function guessEmail(mx) {
    const s = mx.join(' ').toLowerCase();
    if (!s) return null;
    if (s.includes('google') || s.includes('googlemail')) return 'Google Workspace';
    if (s.includes('outlook') || s.includes('microsoft')) return 'Microsoft 365';
    if (s.includes('zoho')) return 'Zoho Mail';
    if (s.includes('pphosted') || s.includes('proofpoint')) return 'Proofpoint';
    if (s.includes('mimecast')) return 'Mimecast';
    if (s.includes('protonmail')) return 'Proton Mail';
    return 'Other';
}

log.info(`Checking ${list.length} websites against ${TECH_COUNT} technology fingerprints.`);
let stop = false;
let ok = 0;
const queue = [...list];
const workers = deepScan ? Math.max(1, Math.min(maxConcurrency, 4)) : Math.max(1, Math.min(maxConcurrency, 20));
await Promise.all(Array.from({ length: workers }, async () => {
    while (queue.length && !stop) {
        const site = queue.shift();
        const row = await inspect(site);
        if (row.status === 'ok') {
            // Only successfully fetched sites are charged.
            const r = await Actor.pushData(row, deepScan ? 'website-deep-scanned' : 'website-scanned');
            ok++;
            if (r?.eventChargeLimitReached) { stop = true; log.warning('Your maximum cost for this run was reached, stopping.'); }
        } else {
            await Actor.pushData(row);
        }
        log.info(`${site}: ${row.status}${row.technologyCount !== undefined ? `, ${row.technologyCount} technologies` : ''}`);
    }
}));
if (browserPromise) await (await browserPromise).close().catch(() => {});
await Actor.setStatusMessage(`Scanned ${ok} of ${list.length} websites.`, { isStatusMessageTerminal: true });
await Actor.exit();
