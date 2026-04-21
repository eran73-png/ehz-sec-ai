// set-project-root.js — Called by installer to save project_root to whitelist.json
// Usage: node set-project-root.js "C:/MyProject"

const fs = require('fs');
const path = require('path');

const projectRoot = process.argv[2];
if (!projectRoot) {
  console.error('Usage: node set-project-root.js <project-path>');
  process.exit(1);
}

// Normalize to forward slashes
const normalized = projectRoot.replace(/\\/g, '/');

// Find whitelist.json — try multiple locations
const locations = [
  path.join(__dirname, '..', 'agent', 'whitelist.json'),
  path.join(__dirname, 'agent', 'whitelist.json'),  // if script is in install/
  path.resolve(path.dirname(process.argv[1]), '..', 'agent', 'whitelist.json')
];

let wlPath = null;
for (const loc of locations) {
  if (fs.existsSync(loc)) {
    wlPath = loc;
    break;
  }
}

if (!wlPath) {
  console.error('whitelist.json not found in:', locations);
  process.exit(1);
}

try {
  const wl = JSON.parse(fs.readFileSync(wlPath, 'utf8'));
  wl.project_root = normalized;
  fs.writeFileSync(wlPath, JSON.stringify(wl, null, 2), 'utf8');
  console.log('OK: project_root set to', normalized, 'in', wlPath);
} catch (e) {
  console.error('Failed:', e.message);
  process.exit(1);
}
