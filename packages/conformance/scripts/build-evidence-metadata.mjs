// SPDX-License-Identifier: Apache-2.0
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { repositoryMetadata } from '../src/evidenceScope.mjs';
const root = fileURLToPath(new URL('../../../', import.meta.url));
writeFileSync(new URL('../dist/evidence-metadata.json', import.meta.url), JSON.stringify(repositoryMetadata(root), null, 2) + '\n');
