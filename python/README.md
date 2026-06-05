# auditguard — Python Client

```bash
pip install requests
```

```python
from auditguard import AuditGuard

client = AuditGuard()
report = client.audit("https://example.com")

print(f"Grade: {report.grade}  Score: {report.score}/100")
print(f"CVE findings: {len(report.cve_findings)}")

for f in report.critical_findings:
    print(f"\n[{f.severity.upper()}] {f.category}: {f.title}")
    if f.interpretation_note:
        print(f"  ⚠️  {f.interpretation_note}")
```

See the [root README](../README.md) for full API documentation.
