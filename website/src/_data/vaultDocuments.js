import { readFileSync } from 'node:fs';

// Render the canonical documents at build time, without a second copy to maintain.
export default [
  { file: 'VAULT.md', slug: 'vault', title: 'Vault protocol',
    description: 'Item encryption, local persistence, automatic connection, and synchronization.' },
  { file: 'VALIDATION.md', slug: 'vault-validation', title: 'Vault validation',
    description: 'Recorded physical checks and remaining automated, hardware, and release acceptance.' }
].map((document) => ({
  ...document,
  content: readFileSync(new URL(`../../../docs/${document.file}`, import.meta.url), 'utf8').replace(/\]\((?!https?:)([^)#]+\.md)(#[^)]*)?\)/g, (_, path, anchor = '') => `](https://github.com/koehn/2ndPass/blob/main/docs/${path}${anchor})`)
}));
