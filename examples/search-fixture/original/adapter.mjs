// rea-bot adapter: one JSON case on stdin -> JSON result on stdout. Imports the owned original unchanged.
import { readFileSync } from 'node:fs';
import { search } from './search.mjs';
const c = JSON.parse(readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(search(c.items, c.query)));
