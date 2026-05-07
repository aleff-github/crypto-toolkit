'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf8'));

test('package.json does not contain redundant explicit activationEvents', () => {
  assert.equal(Object.hasOwn(pkg, 'activationEvents'), false);
});

test('all contributed commands are unique and reachable from Crypto menus', () => {
  const commands = pkg.contributes.commands.map((entry) => entry.command);
  assert.equal(new Set(commands).size, commands.length, 'command ids must be unique');

  const menus = pkg.contributes.menus;
  const menuCommandIds = Object.entries(menus)
    .filter(([menuId]) => menuId.startsWith('cryptoToolkit.menu.'))
    .flatMap(([, entries]) => entries.map((entry) => entry.command).filter(Boolean));

  for (const command of commands) {
    assert.ok(menuCommandIds.includes(command), `${command} is not reachable from a Crypto submenu`);
  }
});

test('root Crypto menu is available at cursor, while selection-only categories stay guarded', () => {
  const contextEntries = pkg.contributes.menus['editor/context'];
  assert.equal(contextEntries.length, 1);
  assert.equal(contextEntries[0].submenu, 'cryptoToolkit.menu.root');
  assert.equal(contextEntries[0].when, 'editorTextFocus');

  const root = pkg.contributes.menus['cryptoToolkit.menu.root'];
  const utility = root.find((entry) => entry.submenu === 'cryptoToolkit.menu.utility');
  assert.ok(utility, 'Utility submenu should be present');
  assert.equal(utility.when, undefined, 'Utility must work without a text selection for generators');

  for (const submenu of ['cryptoToolkit.menu.encode', 'cryptoToolkit.menu.decode', 'cryptoToolkit.menu.hash', 'cryptoToolkit.menu.jwt']) {
    const entry = root.find((item) => item.submenu === submenu);
    assert.ok(entry, `${submenu} should be present`);
    assert.match(entry.when, /editorHasSelection/);
  }
});

test('cleanup removes confusing advanced JWT, recipes, web-security, and regex menu entries', () => {
  const commandIds = pkg.contributes.commands.map((entry) => entry.command);
  assert.ok(commandIds.includes('cryptoToolkit.jwt.decode'));
  assert.equal(commandIds.some((id) => id.includes('.jwt.sign.')), false);
  assert.equal(commandIds.some((id) => id.includes('.jwt.verify.')), false);
  assert.equal(commandIds.some((id) => id.includes('.recipe.')), false);
  assert.equal(commandIds.some((id) => id.includes('.web.')), false);
  assert.equal(commandIds.includes('cryptoToolkit.utility.regexExtract'), false);
});

test('action-only release contains no Workbench Activity Bar or WebView contributions', () => {
  assert.equal(pkg.contributes.viewsContainers, undefined);
  assert.equal(pkg.contributes.views, undefined);

  const serialized = JSON.stringify(pkg.contributes);
  assert.equal(/workbench/i.test(serialized), false, 'package contributions must not mention Workbench');
  assert.equal(/webview/i.test(serialized), false, 'package contributions must not include WebView entries');

  const commandIds = pkg.contributes.commands.map((entry) => entry.command.toLowerCase());
  assert.equal(commandIds.some((id) => id.includes('workbench')), false);
});
