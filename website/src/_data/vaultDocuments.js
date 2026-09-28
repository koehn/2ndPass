import { readFileSync } from 'node:fs';

// Render the canonical documents at build time, without a second copy to maintain.
export default [
  { file: 'VAULT-V7.md', slug: 'vault', title: 'Vault protocol',
    description: 'The v7 vault format, item encryption, membership changes, and publication.' },
  { file: 'V7-VALIDATION-2026-09-27.md', slug: 'vault-validation', title: 'Vault validation',
    description: 'Recorded v7 test results, hardware measurements, and remaining live acceptance checks as of September 27, 2026.' }
].map((document) => ({
  ...document,
  content: readFileSync(new URL(`../../../docs/${document.file}`, import.meta.url), 'utf8')
}));
