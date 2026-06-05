# auditguard — JavaScript/Node.js Client

```bash
npm install auditguard
```

```js
import { AuditGuard } from 'auditguard';

const client = new AuditGuard();
const report = await client.audit('https://example.com');

console.log(`Grade: ${report.grade}  Score: ${report.score}/100`);
console.log(`CVE findings: ${report.cveFindings.length}`);

report.criticalFindings.forEach(f => {
  console.log(`[${f.category}] ${f.title}`);
  if (f.interpretationNote) console.log(`  ⚠️ ${f.interpretationNote}`);
});
```

TypeScript types included. See the [root README](../README.md) for full documentation.
