#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const root = process.cwd();
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const errors = [];
const warnings = [];
for (const name of ['name','displayName','description','version','publisher','license','engines','main']) {
  if (!pkg[name]) errors.push(`package.json is missing ${name}`);
}
if (pkg.publisher && /your-publisher|change|replace|todo/i.test(pkg.publisher)) errors.push(`publisher looks like a placeholder: ${pkg.publisher}`);
if (!pkg.repository || !pkg.repository.url) errors.push('package.json is missing repository.url');
if (!pkg.icon) errors.push('package.json is missing icon');
else {
  const iconPath = path.join(root, pkg.icon);
  if (!fs.existsSync(iconPath)) errors.push(`icon file does not exist: ${pkg.icon}`);
  if (!/\.png$/i.test(pkg.icon)) errors.push('Marketplace icon must be PNG');
}
for (const file of ['README.md','CHANGELOG.md','LICENSE','PRIVACY.md','SECURITY.md','SUPPORT.md']) {
  if (!fs.existsSync(path.join(root, file))) warnings.push(`missing ${file}`);
}
if (pkg.keywords && pkg.keywords.length > 30) errors.push(`too many keywords: ${pkg.keywords.length}`);
if (errors.length) { console.error(errors.map(e=>`- ${e}`).join('\n')); process.exit(1); }
if (warnings.length) console.warn(warnings.map(w=>`- ${w}`).join('\n'));
console.log('Marketplace verification passed.');
