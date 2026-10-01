// Technology detection using the open-source webappanalyzer fingerprints (GPL-3.0).
// Follows the usual fingerprint format: "regex\;version:\1\;confidence:50".
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as cheerio from 'cheerio';

const DATA = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');

const categories = JSON.parse(fs.readFileSync(path.join(DATA, 'categories.json'), 'utf8'));
const groups = JSON.parse(fs.readFileSync(path.join(DATA, 'groups.json'), 'utf8'));

function parsePattern(raw) {
    const [regex, ...tags] = String(raw).split('\\;');
    const p = { confidence: 100, version: '' };
    for (const t of tags) {
        const i = t.indexOf(':');
        const k = t.slice(0, i);
        const v = t.slice(i + 1);
        if (k === 'confidence') p.confidence = Number(v) || 0;
        else if (k === 'version') p.version = v;
    }
    try {
        // Fingerprints are written for JS regex; keep them case-insensitive like the reference tools.
        p.regex = new RegExp(regex.replace('/', '\\/'), 'i');
    } catch {
        p.regex = null;
    }
    return p;
}

const toArray = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
const parseList = (v) => toArray(v).map(parsePattern).filter((p) => p.regex);
const parseChains = (v) => {
    const out = {};
    if (v && typeof v === 'object' && !Array.isArray(v)) for (const [k, pats] of Object.entries(v)) out[k] = parseList(pats);
    return out;
};
const parseMap = (v) => {
    const out = {};
    if (v && typeof v === 'object' && !Array.isArray(v)) {
        for (const [k, pats] of Object.entries(v)) out[k.toLowerCase()] = parseList(pats);
    }
    return out;
};

const TECH = [];
for (const f of fs.readdirSync(path.join(DATA, 'technologies'))) {
    const json = JSON.parse(fs.readFileSync(path.join(DATA, 'technologies', f), 'utf8'));
    for (const [name, t] of Object.entries(json)) {
        TECH.push({
            name,
            cats: t.cats || [],
            website: t.website || null,
            description: t.description || null,
            oss: !!t.oss,
            saas: !!t.saas,
            pricing: t.pricing || [],
            html: parseList(t.html),
            text: parseList(t.text),
            scriptSrc: parseList(t.scriptSrc),
            scripts: parseList(t.scripts),
            url: parseList(t.url),
            robots: parseList(t.robots),
            certIssuer: parseList(t.certIssuer),
            meta: parseMap(t.meta),
            headers: parseMap(t.headers),
            cookies: parseMap(t.cookies),
            dns: parseMap(t.dns),
            dom: t.dom,
            js: parseChains(t.js),
            xhr: parseList(t.xhr),
            implies: toArray(t.implies).map(parsePattern),
            excludes: toArray(t.excludes).map((s) => String(s).split('\\;')[0]),
            requires: toArray(t.requires).map((s) => String(s).split('\\;')[0]),
            requiresCategory: toArray(t.requiresCategory).map(Number),
        });
    }
}
const BY_NAME = new Map(TECH.map((t) => [t.name, t]));
export const TECH_COUNT = TECH.length;
export const JS_CHAINS = [...new Set(TECH.flatMap((t) => Object.keys(t.js)))];

function resolveVersion(template, match) {
    if (!template) return '';
    let v = template;
    for (let i = 0; i < match.length; i++) {
        const g = match[i] ?? '';
        // Ternary syntax: \1?yes:no
        v = v.replace(new RegExp(`\\\\${i}\\?([^:]*):(.*)$`), (_, yes, no) => (g ? yes : no));
        v = v.split(`\\${i}`).join(g);
    }
    return v.trim().length > 30 ? '' : v.trim();
}

function test(p, value) {
    if (value === undefined || value === null) return null;
    const m = p.regex.exec(String(value).slice(0, 500000));
    return m ? { confidence: p.confidence, version: resolveVersion(p.version, m) } : null;
}

function domMatches(tech, $) {
    const out = [];
    const spec = tech.dom;
    if (!spec) return out;
    if (typeof spec === 'string' || Array.isArray(spec)) {
        for (const sel of toArray(spec)) {
            try { if ($(sel).length) out.push({ confidence: 100, version: '' }); } catch { /* unsupported selector */ }
        }
        return out;
    }
    for (const [sel, rules] of Object.entries(spec)) {
        let els;
        try { els = $(sel); } catch { continue; }
        if (!els.length) continue;
        if (rules.exists !== undefined) out.push({ confidence: 100, version: '' });
        if (rules.text !== undefined) {
            const p = parsePattern(rules.text);
            els.each((_, el) => { const r = p.regex && test(p, $(el).text()); if (r) out.push(r); });
        }
        if (rules.attributes) {
            for (const [attr, pat] of Object.entries(rules.attributes)) {
                const p = parsePattern(pat);
                els.each((_, el) => { const r = p.regex && test(p, $(el).attr(attr)); if (r) out.push(r); });
            }
        }
        // "properties" need a real browser (JS objects); skipped.
    }
    return out;
}

/**
 * page: { url, html, headers{lower: string}, cookies{name: value}, robots, dns{mx:[],txt:[],ns:[],cname:[]}, certIssuer }
 */
export function analyze(page) {
    const $ = cheerio.load(page.html || '');
    const scriptSrc = $('script[src]').map((_, el) => $(el).attr('src')).get();
    const inlineScripts = $('script:not([src])').map((_, el) => $(el).html()).get().join('\n');
    const meta = {};
    $('meta').each((_, el) => {
        const k = ($(el).attr('name') || $(el).attr('property') || $(el).attr('http-equiv') || '').toLowerCase();
        if (k) meta[k] = [...(meta[k] || []), $(el).attr('content') || ''];
    });
    const text = $('body').text().replace(/\s+/g, ' ').slice(0, 200000);

    const hits = new Map(); // name -> {confidence, version}
    const add = (tech, r) => {
        if (!r) return;
        const cur = hits.get(tech.name) || { confidence: 0, version: '' };
        cur.confidence = Math.min(100, cur.confidence + r.confidence);
        if (r.version && (!cur.version || r.version.length > cur.version.length)) cur.version = r.version;
        hits.set(tech.name, cur);
    };

    for (const t of TECH) {
        for (const p of t.url) add(t, test(p, page.url));
        for (const p of t.html) add(t, test(p, page.html));
        for (const p of t.text) add(t, test(p, text));
        for (const p of t.scripts) add(t, test(p, inlineScripts));
        for (const p of t.robots) add(t, test(p, page.robots));
        for (const p of t.certIssuer) add(t, test(p, page.certIssuer));
        for (const p of t.scriptSrc) for (const s of scriptSrc) { const r = test(p, s); if (r) { add(t, r); break; } }
        for (const [k, pats] of Object.entries(t.headers)) {
            if (page.headers[k] === undefined) continue;
            for (const p of pats) add(t, p.regex.source === '' ? { confidence: p.confidence, version: '' } : test(p, page.headers[k]));
        }
        for (const [k, pats] of Object.entries(t.cookies)) {
            const name = Object.keys(page.cookies).find((c) => c.toLowerCase() === k || (k.endsWith('*') && c.toLowerCase().startsWith(k.slice(0, -1))));
            if (name === undefined) continue;
            for (const p of pats) add(t, p.regex.source === '' ? { confidence: p.confidence, version: '' } : test(p, page.cookies[name]));
        }
        for (const [k, pats] of Object.entries(t.meta)) {
            for (const v of meta[k] || []) for (const p of pats) add(t, test(p, v));
        }
        for (const [k, pats] of Object.entries(t.dns)) {
            for (const v of page.dns?.[k] || []) for (const p of pats) add(t, test(p, v));
        }
        if (t.dom) for (const r of domMatches(t, $)) add(t, r);
        if (page.js) {
            for (const [chain, pats] of Object.entries(t.js)) {
                if (!(chain in page.js)) continue;
                for (const p of pats) add(t, p.regex.source === '' || p.regex.source === '(?:)' ? { confidence: p.confidence, version: '' } : test(p, page.js[chain]));
            }
        }
        if (page.requests?.length) {
            for (const p of t.xhr) for (const u of page.requests) { const r = test(p, u); if (r) { add(t, r); break; } }
            for (const p of t.scriptSrc) for (const u of page.requests) { const r = test(p, u); if (r) { add(t, r); break; } }
        }
    }

    // Implied technologies (e.g. WordPress implies PHP + MySQL).
    let changed = true;
    while (changed) {
        changed = false;
        for (const [name, h] of [...hits]) {
            for (const imp of BY_NAME.get(name)?.implies || []) {
                const target = imp.regex?.source.replace(/\\\//g, '/');
                if (target && BY_NAME.has(target) && !hits.has(target)) {
                    hits.set(target, { confidence: Math.min(h.confidence, imp.confidence), version: '', implied: true });
                    changed = true;
                }
            }
        }
    }
    // Requirements and exclusions.
    const catsPresent = new Set([...hits.keys()].flatMap((n) => BY_NAME.get(n).cats));
    for (const name of [...hits.keys()]) {
        const t = BY_NAME.get(name);
        if (t.requires.length && !t.requires.some((r) => hits.has(r))) hits.delete(name);
        else if (t.requiresCategory.length && !t.requiresCategory.some((c) => catsPresent.has(c))) hits.delete(name);
    }
    for (const name of [...hits.keys()]) for (const ex of BY_NAME.get(name)?.excludes || []) hits.delete(ex);

    return [...hits].filter(([, h]) => h.confidence >= 50).map(([name, h]) => {
        const t = BY_NAME.get(name);
        const cats = t.cats.map((c) => categories[c]).filter(Boolean);
        return {
            name,
            version: h.version || null,
            confidence: h.confidence,
            categories: cats.map((c) => c.name),
            groups: [...new Set(cats.flatMap((c) => c.groups || []).map((g) => groups[g]?.name).filter(Boolean))],
            website: t.website,
            description: t.description,
            openSource: t.oss,
            saas: t.saas,
            pricing: t.pricing,
            implied: !!h.implied,
        };
    }).sort((a, b) => (a.categories[0] || '').localeCompare(b.categories[0] || '') || a.name.localeCompare(b.name));
}
