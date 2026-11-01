#!/usr/bin/env node
'use strict';

// Guards the panel and agent translations. Spanish is the source key and the
// other nine languages must contain every entry. Explicit T()/TF() strings in
// the SPA must also exist in the English dictionary.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const i18nPath = path.join(root, 'web', 'i18n.js');
const appPath = path.join(root, 'web', 'app.js');
const i18n = fs.readFileSync(i18nPath, 'utf8');
const app = fs.readFileSync(appPath, 'utf8');

function objectAfter(source, marker) {
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`missing ${marker}`);
  let index = source.indexOf('{', start);
  let depth = 0;
  for (; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    else if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) {
        return source.slice(source.indexOf('{', start), index + 1);
      }
    }
  }
  throw new Error(`unterminated ${marker}`);
}

const languages = ['EN', 'PT', 'FR', 'AR', 'RU', 'ZH', 'JA', 'IT', 'DE'];
const dictionaries = {};
for (const language of languages) {
  dictionaries[language] = vm.runInNewContext(
    `(${objectAfter(i18n, `const ${language} = {`)})`,
  );
}

const failures = [];
const enKeys = new Set(Object.keys(dictionaries.EN));
for (const language of languages.slice(1)) {
  const missing = [...enKeys].filter((key) => !(key in dictionaries[language]));
  if (missing.length) {
    failures.push(`${language} is missing ${missing.length} key(s):`);
    for (const key of missing) failures.push(`  - ${JSON.stringify(key)}`);
  }
}

const used = new Set();
const patterns = [
  /\bT(?:F)?\(\s*(['"])((?:\\.|(?!\1).)*)\1/g,
  /sectionHead\(\s*'((?:\\.|[^'\\])*)'/g,
  /toast\(\s*'((?:\\.|[^'\\])*)'/g,
  /title:\s*'((?:\\.|[^'\\])*)'/g,
  /\bfInput\(\s*'[^']*'\s*,\s*'((?:\\.|[^'\\])*)'/g,
  /\bfSelect\(\s*'[^']*'\s*,\s*'((?:\\.|[^'\\])*)'/g,
  /\bfCheck\(\s*'[^']*'\s*,\s*'((?:\\.|[^'\\])*)'/g,
  /\bfield\(\s*'[^']*'\s*,\s*'((?:\\.|[^'\\])*)'/g,
  /\bshowOutput\(\s*'((?:\\.|[^'\\])*)'/g,
];
// Technical labels and product names intentionally stay in their source form.
const technical = new Set([
  'Alias',
  'Cron',
  'Entrypoint',
  'FTP',
  'Laravel',
  'Max children',
  'PHP-FPM',
  'Runtime',
  'SSH',
  'TLS',
  'TTL',
  'WordPress',
]);
for (const pattern of patterns) {
  let match;
  while ((match = pattern.exec(app))) {
    const text = (match[2] !== undefined ? match[2] : match[1]).replace(
      /\\(['"\\])/g,
      '$1',
    );
    if (
      text &&
      !/[{}]/.test(text) &&
      !/^[a-z_]+$/.test(text) &&
      !technical.has(text)
    ) {
      used.add(text);
    }
  }
}

const untranslated = [...used].filter((text) => !enKeys.has(text));
if (untranslated.length) {
  failures.push(`app.js uses ${untranslated.length} string(s) missing from EN:`);
  for (const text of untranslated) failures.push(`  - ${JSON.stringify(text)}`);
}

if (failures.length) {
  console.error('i18n check failed:\n' + failures.join('\n'));
  process.exit(1);
}
console.log(
  `i18n OK: ${enKeys.size} keys in ${languages.length} languages, ` +
    `${used.size} explicit UI strings covered`,
);
