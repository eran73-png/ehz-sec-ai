'use strict';
/**
 * FlowGuard License Manager — v2.9.1
 * Trial 60 days → Free tier → Pro with License Key
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const LICENSE_PATH = path.join(__dirname, '..', 'license.json');
const TRIAL_DAYS   = 60;
const WARN_DAYS    = 5;  // alert 5 days before expiry

// ─── Encryption helpers (simple AES-256 to prevent casual editing) ────────────
const ENC_KEY = crypto.createHash('sha256').update('FlowGuard-EHZ-AI-2026').digest();
const ENC_IV  = Buffer.alloc(16, 0);

function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, ENC_IV);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function decrypt(hex) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, ENC_IV);
  return decipher.update(hex, 'hex', 'utf8') + decipher.final('utf8');
}

// ─── Load / Save ──────────────────────────────────────────────────────────────
function loadLicense() {
  try {
    const raw = fs.readFileSync(LICENSE_PATH, 'utf8').trim();
    // Try encrypted format first
    try {
      return JSON.parse(decrypt(raw));
    } catch (_) {
      // Fallback: plain JSON (first run or migration)
      return JSON.parse(raw);
    }
  } catch (_) {
    return null;
  }
}

function saveLicense(data) {
  const json = JSON.stringify(data, null, 2);
  fs.writeFileSync(LICENSE_PATH, encrypt(json), 'utf8');
}

// ─── Init (called on first install) ──────────────────────────────────────────
function initLicense() {
  let lic = loadLicense();
  if (lic && lic.install_date) return lic;

  lic = {
    install_date: new Date().toISOString(),
    key: 'TRIAL',
    plan: 'trial',
    valid: true,
  };
  saveLicense(lic);
  return lic;
}

// ─── Check License Status ────────────────────────────────────────────────────
function checkLicense() {
  const lic = initLicense();

  // Pro license — always valid
  if (lic.plan === 'pro' && lic.key !== 'TRIAL') {
    return {
      plan: 'pro',
      valid: true,
      daysLeft: null,
      showWarning: false,
      expired: false,
      message: 'Pro License — All features unlocked',
    };
  }

  // Calculate trial days
  const installDate = new Date(lic.install_date);
  const now = new Date();
  const elapsed = Math.floor((now - installDate) / (1000 * 60 * 60 * 24));
  const daysLeft = Math.max(0, TRIAL_DAYS - elapsed);
  const expired = daysLeft === 0;
  const showWarning = !expired && daysLeft <= WARN_DAYS;

  if (expired) {
    return {
      plan: 'free',
      valid: true,
      daysLeft: 0,
      showWarning: false,
      expired: true,
      message: 'Trial ended — Free plan active. Upgrade to Pro for all features.',
    };
  }

  return {
    plan: 'trial',
    valid: true,
    daysLeft,
    showWarning,
    expired: false,
    message: showWarning
      ? `Trial ends in ${daysLeft} day${daysLeft === 1 ? '' : 's'} — Enter license key to continue Pro features`
      : null, // No message during silent trial period
  };
}

// ─── Feature Gating ──────────────────────────────────────────────────────────
const PRO_FEATURES = [
  'telegram_alerts',
  'skills_intelligence',
  'behavioral_learning',
  'multi_machine',
  'qa_suite',
  'export_siem',
];

function isFeatureEnabled(feature) {
  const status = checkLicense();
  // Trial and Pro: everything enabled
  if (status.plan === 'trial' || status.plan === 'pro') return true;
  // Free: only non-pro features
  return !PRO_FEATURES.includes(feature);
}

// ─── Activate License Key ────────────────────────────────────────────────────
function activateLicense(key) {
  // Validate format: FG-XXXX-XXXX-XXXX
  if (!/^FG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(key)) {
    return { success: false, error: 'Invalid key format. Expected: FG-XXXX-XXXX-XXXX' };
  }

  // Checksum: last 4 chars = first 4 of SHA256 of first 8 chars
  const parts = key.replace('FG-', '').split('-');
  const payload = parts[0] + parts[1];
  const expected = crypto.createHash('sha256').update(payload).digest('hex').slice(0, 4).toUpperCase();
  if (parts[2] !== expected) {
    return { success: false, error: 'Invalid license key' };
  }

  const lic = loadLicense() || {};
  lic.key = key;
  lic.plan = 'pro';
  lic.activated_date = new Date().toISOString();
  saveLicense(lic);

  return { success: true, plan: 'pro', message: 'License activated — Pro plan enabled' };
}

// ─── Generate a valid key (for admin use) ────────────────────────────────────
function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let p1 = '', p2 = '';
  for (let i = 0; i < 4; i++) {
    p1 += chars[Math.floor(Math.random() * chars.length)];
    p2 += chars[Math.floor(Math.random() * chars.length)];
  }
  const checksum = crypto.createHash('sha256').update(p1 + p2).digest('hex').slice(0, 4).toUpperCase();
  return `FG-${p1}-${p2}-${checksum}`;
}

module.exports = {
  checkLicense,
  isFeatureEnabled,
  activateLicense,
  generateKey,
  initLicense,
  PRO_FEATURES,
};
