#!/usr/bin/env python3
"""
Базовый пример: технический аудит одного сайта.
"""
import sys
sys.path.insert(0, '..')

from auditguard import AuditGuard

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"

    print(f"Запуск аудита: {url}")
    client = AuditGuard()
    report = client.audit(url)

    print(f"\n{'='*60}")
    print(f"URL:   {report.url}")
    print(f"Grade: {report.grade}  Score: {report.score}/100")
    print(f"Всего находок: {report.total_findings}")
    print(f"  critical: {report.summary.get('critical', 0)}")
    print(f"  high:     {report.summary.get('high', 0)}")
    print(f"  medium:   {report.summary.get('medium', 0)}")
    print(f"  low:      {report.summary.get('low', 0)}")
    print(f"{'='*60}\n")

    # CVE findings
    cve = report.cve_findings
    if cve:
        print(f"🛡️  CVE-находки ({len(cve)} шт.):")
        for f in cve:
            severity_icon = {'critical': '🚨', 'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(f.severity, '⚪')
            print(f"\n  {severity_icon} [{f.id}] {f.title}")
            if f.interpretation_note:
                print(f"     ⚠️  {f.interpretation_note}")
            print(f"     Риск: {f.why_risk[:150]}")
        print()

    # Critical
    if report.critical_findings:
        print("🚨 КРИТИЧЕСКИЕ НАРУШЕНИЯ:")
        for f in report.critical_findings:
            print(f"\n  [{f.id}] {f.title}")
            print(f"  Где: {f.where}")
            print(f"  Риск: {f.why_risk[:200]}")
            print(f"  Исправить: {f.fix[:200]}")
    else:
        print("✅ Критических нарушений не найдено")


if __name__ == "__main__":
    main()
