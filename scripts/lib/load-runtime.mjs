// Loads the browser runtime scripts (search-index.js, search-core.js) the way a
// browser does: as classic scripts sharing one global object.
//
// Do NOT switch this to require(): the package is "type": "module", so a .js
// file gets loaded as ESM and the UMD `module.exports` branch never runs,
// leaving ForensicSearch undefined. Evaluating in a vm context is also closer
// to what actually happens over file://.

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { ROOT, DIST } from './site.mjs';

const INDEX_FILE = path.join(DIST, 'assets', 'search-index.js');
const CORE_FILE = path.join(ROOT, 'assets', 'search-core.js');

/**
 * @returns {{ index: object, Search: object }}
 * @throws if dist has not been built yet
 */
export function loadSearchRuntime() {
  for (const f of [INDEX_FILE, CORE_FILE]) {
    if (!fs.existsSync(f)) {
      throw new Error(`missing ${path.relative(ROOT, f)} — run node scripts/build.mjs first`);
    }
  }

  const globals = {};
  globals.window = globals;
  globals.self = globals;
  const sandbox = vm.createContext(globals);

  for (const file of [INDEX_FILE, CORE_FILE]) {
    vm.runInContext(fs.readFileSync(file, 'utf8'), sandbox, {
      filename: path.relative(ROOT, file),
    });
  }

  const index = globals.FORENSIC_INDEX;
  const Search = globals.ForensicSearch;
  if (!index) throw new Error('search-index.js did not define FORENSIC_INDEX');
  if (!Search || typeof Search.search !== 'function') {
    throw new Error('search-core.js did not define ForensicSearch.search');
  }
  return { index, Search };
}
