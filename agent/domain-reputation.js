'use strict';
/**
 * EHZ-SEC-AI — Domain Reputation Engine
 * Milestone 6.10
 *
 * ציון אמינות 0-100 לדומיין (offline, ללא API חיצוני)
 * מבוסס: TLD reputation, דפוסים חשודים, רשימה שחורה, אורך, מקפים
 */

// ─── TLD Reputation ───────────────────────────────────────────────────────────

const TLD_GOOD = new Set([
  'com','org','net','io','dev','app','co','ai','tech','cloud',
  'gov','edu','mil','int','eu','uk','de','fr','nl','se','no',
  'il','us','ca','au','jp','ch','at','be','dk','fi',
]);

const TLD_BAD = new Set([
  'ru','cn','tk','ml','ga','cf','gq','xyz','top','click',
  'win','download','loan','racing','party','science','men',
  'work','date','faith','review','accountant','stream',
  'trade','webcam','bid','cricket','kim',
]);

// ─── Offline Blacklist (דומיינים ידועים כמזיקים) ─────────────────────────────

const BLACKLIST = new Set([
  'malware.com','phishing.net','evilcorp.ru','darkweb.onion',
  'freebitcoin.win','cryptominer.xyz','ransomware.top',
]);

// ─── Suspicious Patterns ─────────────────────────────────────────────────────

const SUSPICIOUS_KEYWORDS = [
  'login-','secure-','verify-','account-','update-','confirm-',
  'banking-','paypal-','amazon-','microsoft-','apple-','google-',
  '-login','-secure','-verify','-update','-confirm','-support',
];

// ─── Score Engine ─────────────────────────────────────────────────────────────

/**
 * @param {string} domain — hostname (e.g. "evil.ru" or "github.com")
 * @param {string[]} allowedDomains — מרשימת allowed_domains
 * @returns {{ score: number, label: string, color: string, reasons: string[] }}
 */
function scoreDomain(domain, allowedDomains = []) {
  const d       = domain.toLowerCase().replace(/^www\./, '');
  const parts   = d.split('.');
  const tld     = parts[parts.length - 1];
  const sld     = parts[parts.length - 2] || '';  // second-level domain
  const reasons = [];
  let score     = 50; // neutral start

  // ── Blacklist ──
  if (BLACKLIST.has(d)) {
    return { score: 0, label: 'BLACKLISTED', color: '#7f1d1d', reasons: ['נמצא ברשימה שחורה'] };
  }

  // ── Allowed list ──
  const inAllowed = allowedDomains.some(a => {
    const an = a.toLowerCase().replace(/^https?:\/\//, '');
    return d === an || d.endsWith('.' + an);
  });
  if (inAllowed) { score += 35; reasons.push('ברשימת הדומיינים המורשים (+35)'); }

  // ── TLD ──
  if (TLD_GOOD.has(tld))      { score += 15; reasons.push(`TLD מהימן (.${tld}) (+15)`); }
  else if (TLD_BAD.has(tld))  { score -= 40; reasons.push(`TLD חשוד (.${tld}) (-40)`); }
  else                         { score -= 5;  reasons.push(`TLD לא מוכר (.${tld}) (-5)`); }

  // ── Hyphens ──
  const hyphens = (sld.match(/-/g) || []).length;
  if (hyphens >= 3)      { score -= 20; reasons.push(`${hyphens} מקפים בדומיין (-20)`); }
  else if (hyphens >= 1) { score -= 5;  reasons.push(`${hyphens} מקפים בדומיין (-5)`); }

  // ── Numbers ──
  const nums = (sld.match(/\d/g) || []).length;
  if (nums >= 4)      { score -= 15; reasons.push(`${nums} ספרות בדומיין (-15)`); }
  else if (nums >= 2) { score -= 5;  reasons.push(`${nums} ספרות בדומיין (-5)`); }

  // ── Domain length ──
  if (d.length > 40)      { score -= 15; reasons.push(`דומיין ארוך מאוד (${d.length} תווים) (-15)`); }
  else if (d.length > 25) { score -= 5;  reasons.push(`דומיין ארוך (${d.length} תווים) (-5)`); }

  // ── Suspicious keywords ──
  const foundKw = SUSPICIOUS_KEYWORDS.find(kw => sld.includes(kw));
  if (foundKw) { score -= 25; reasons.push(`מילת מפתח חשודה: "${foundKw}" (-25)`); }

  // ── Punycode / IDN ──
  if (d.includes('xn--')) { score -= 20; reasons.push('Punycode / IDN domain (-20)'); }

  // ── Very short domain ──
  if (sld.length <= 2) { score += 5; reasons.push('דומיין קצר — לרוב מהימן (+5)'); }

  score = Math.max(0, Math.min(100, score));

  let label, color;
  if (score >= 80)      { label = 'TRUSTED';    color = '#10b981'; }
  else if (score >= 60) { label = 'OK';         color = '#84cc16'; }
  else if (score >= 40) { label = 'NEUTRAL';    color = '#f59e0b'; }
  else if (score >= 20) { label = 'SUSPICIOUS'; color = '#f97316'; }
  else                  { label = 'MALICIOUS';  color = '#ef4444'; }

  return { score, label, color, reasons };
}

module.exports = { scoreDomain };
