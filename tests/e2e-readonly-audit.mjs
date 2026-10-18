import fs from 'node:fs';
import path from 'node:path';
import { chromium, devices } from 'playwright';

const out = path.resolve('audit-results');
fs.mkdirSync(out, { recursive: true });
const base = process.env.AUDIT_BASE_URL || 'https://submarine.asia';
const profiles = [
  { name: 'desktop', viewport: { width: 1440, height: 900 } },
  { name: 'mobile-android', ...devices['Pixel 7'] },
  { name: 'mobile-ios', ...devices['iPhone 13'] },
];
const routes = ['/', '/freediving.html', '/admin.html', '/admin-k-mobile.html', '/privacy.html'];
const findings = [];
const checks = [];
const add = (severity, profile, route, kind, message) => findings.push({ severity, profile, route, kind, message: String(message).slice(0, 500) });
const browser = await chromium.launch({ headless: true });
for (const profile of profiles) {
  const context = await browser.newContext({ ...profile, ignoreHTTPSErrors: false });
  for (const route of routes) {
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
    page.on('requestfailed', r => errors.push('request: ' + r.url() + ' ' + r.failure()?.errorText));
    const url = new URL(route, base).href;
    try {
      const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(1200);
      const status = response?.status() ?? 0;
      checks.push({ profile: profile.name, route, status, title: await page.title() });
      if (status >= 400 || !status) add('error', profile.name, route, 'http', 'HTTP ' + status);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 8);
      if (overflow) add('warning', profile.name, route, 'horizontal-overflow', 'Page wider than viewport');
      for (const e of [...new Set(errors)]) add('error', profile.name, route, 'browser-console', e);
      await page.screenshot({ path: path.join(out, profile.name + '-' + route.replace(/[^a-z0-9]/gi, '_') + '.png'), fullPage: true, timeout: 15000 });
    } catch (e) {
      add('error', profile.name, route, 'navigation', e.message);
    } finally { await page.close(); }
  }
  await context.close();
}
await browser.close();
const report = { generatedAt: new Date().toISOString(), base, note: 'Read-only browser smoke audit. No login, reservation, payment, or administrative mutation performed. Mobile profiles are emulated browsers, not native app E2E.', checks, findings, summary: { checks: checks.length, errors: findings.filter(f => f.severity === 'error').length, warnings: findings.filter(f => f.severity === 'warning').length } };
fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify(report, null, 2));
const md = ['# SUBMARINE read-only E2E inventory', '', 'Target: ' + base, '', 'Checks: ' + report.summary.checks + ' | Errors: ' + report.summary.errors + ' | Warnings: ' + report.summary.warnings, '', '| Severity | Profile | Route | Type | Detail |', '|---|---|---|---|---|', ...findings.map(f => '| ' + [f.severity, f.profile, f.route, f.kind, f.message.replace(/[|\n\r]/g, ' ').slice(0, 160)].join(' | ') + ' |'), '', 'This is a read-only smoke test, not a complete authenticated booking E2E. Findings must be reviewed before any fix.'];
fs.writeFileSync(path.join(out, 'report.md'), md.join('\n'));
console.log(JSON.stringify(report.summary));
