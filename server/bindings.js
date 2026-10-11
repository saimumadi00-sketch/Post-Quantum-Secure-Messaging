import fs from 'node:fs';
import path from 'node:path';

// One local relay process. Use a transactional database for multiple instances.
export function createBindingStore(filename) {
  let bindings = fs.existsSync(filename) ? JSON.parse(fs.readFileSync(filename, 'utf8')) : {};
  return {
    bind(fingerprint, userId, publicExport) {
      const existing = bindings[fingerprint];
      if (existing && (existing.userId !== userId || existing.publicExport !== publicExport)) {
        throw new Error('Encryption identity belongs to another account.');
      }
      if (existing) return;
      const next = { ...bindings, [fingerprint]: { userId, publicExport } };
      fs.mkdirSync(path.dirname(filename), { recursive: true });
      fs.writeFileSync(`${filename}.tmp`, JSON.stringify(next), { mode: 0o600 });
      fs.renameSync(`${filename}.tmp`, filename);
      bindings = next;
    },
  };
}
