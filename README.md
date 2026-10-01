# Website Tech Stack Detector

**Detect what any website is built with**: CMS, ecommerce platform, analytics and ad tags,
JavaScript frameworks, CDN, hosting, payment tools, SSL issuer and email provider.
7,600+ technology fingerprints, bulk lists, clean JSON.

**▶ Run it in the cloud, no setup:** [apify.com/swiftkit/tech-stack](https://apify.com/swiftkit/tech-stack)
(API, schedules, integrations with Zapier/Make/Google Sheets, pay per site).

## Run it yourself

```bash
npm install
npx apify-cli run --input '{"websites":["stripe.com","wordpress.org"]}'
```

Deep scan (`"deepScan": true`) needs Playwright with Chromium installed (`npx playwright install chromium`).
Results land in `storage/datasets/default`.

---

Find out what any website is built with. Paste a list of domains, get back the technologies
behind each one: **CMS, ecommerce platform, analytics and ad tags, JavaScript frameworks, CDN,
hosting, payment providers, security tools, SSL issuer and email provider.**

It checks each site against **7,600+ technology fingerprints** from the open-source
[webappanalyzer](https://github.com/enthec/webappanalyzer) project.

## Who it's for

- **Sales and lead generation:** find every Shopify store, WordPress site or HubSpot user in your
  list, and personalize outreach by the tools they already use.
- **Agencies:** audit a prospect's site before the first call.
- **Market research:** count how many sites in a niche use each platform.
- **Competitor tracking:** see when a competitor switches analytics, CMS or hosting.
- **AI agents:** one call, clean JSON, the same fields every time.

## Input

| Field | What it does |
|---|---|
| **Websites** | One per line: `stripe.com` or `https://www.notion.so/pricing`. |
| Deep scan (real browser) | Opens each site in headless Chrome to also catch tools that load with JavaScript. In our tests it found about **2× more technologies** (e.g. 33 → 56 on hubspot.com). |
| Include details | Version, confidence, categories, vendor website, open source or SaaS, for each technology. |
| Check DNS and SSL | Also reads public DNS records and the SSL certificate. Finds the email provider (Google Workspace, Microsoft 365…), DNS host and more. |
| Respect robots.txt | Skips sites that ask all bots to stay away. Skipped sites are free. |

## Output

One row per website:

```json
{
  "domain": "wordpress.org",
  "status": "ok",
  "pageTitle": "Blog Tool, Publishing Platform, and CMS – WordPress.org",
  "technologyCount": 14,
  "technologies": ["WordPress", "PHP", "MySQL", "Nginx", "Google Tag Manager", "Let's Encrypt", "…"],
  "byCategory": {
    "CMS": ["WordPress"],
    "Programming languages": ["PHP"],
    "Databases": ["MySQL"],
    "Web servers": ["Nginx"],
    "Tag managers": ["Google Tag Manager"]
  },
  "emailProvider": "Google Workspace",
  "details": [
    { "name": "WordPress", "version": "6.8", "confidence": 100, "categories": ["CMS", "Blogs"], "openSource": true, "saas": false }
  ]
}
```

`status` is `ok`, `http_403` (the site refused the visit), `unreachable`, `invalid_url` or
`blocked_by_robots_txt`.

## Pricing

You pay **per website scanned successfully**: a fast scan or a deep scan (priced higher because it runs a real browser). Unreachable sites, refused visits and sites skipped
by robots.txt are free. See the Pricing tab.

## How it works, honestly

- It loads each homepage once (fast mode) or opens it in headless Chrome (deep scan), like a normal visitor, and reads the HTML, scripts, meta tags,
  response headers and cookies. With DNS on, it also reads public DNS records and the SSL issuer.
- Fast mode reads the page source without running JavaScript, so tools that only appear after
  JavaScript runs may be missed. Turn on **Deep scan** to catch those.
- Some large sites block automated visits (`http_403`); you're not charged for those.
- Detection is based on public fingerprints. Rare or custom tools may not be listed.

## Open source

This Actor's source code is public under the GPL-3.0 license, as required by the fingerprint
data it uses. Technology fingerprints © webappanalyzer contributors.

## Questions or a wrong detection?

Open an issue on the Issues tab with the site and what you expected.

## License and credits

GPL-3.0. Technology fingerprints come from the open-source
[webappanalyzer](https://github.com/enthec/webappanalyzer) project (GPL-3.0); thank you to its
contributors. Made by [SwiftKit](https://apify.com/swiftkit).
