# AuditGuard — Technical & Cybersecurity Audit API

<p align="center">
  <a href="https://auditguard.ru"><img src="https://img.shields.io/badge/Live%20Service-auditguard.ru-blue?style=for-the-badge" alt="Live Service"/></a>
  <img src="https://img.shields.io/badge/Parameters-438%2B-brightgreen?style=for-the-badge" alt="438+ parameters"/>
  <img src="https://img.shields.io/badge/Directions-9-orange?style=for-the-badge" alt="9 directions"/>
  <img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/API-REST%20JSON-blueviolet?style=for-the-badge" alt="REST API"/>
</p>

<p align="center">
  <strong>Автоматический технический и кибербезопасность-аудит сайтов.</strong><br/>
  438+ параметров · 9 направлений · EPSS + CISA KEV + Shodan · 2–4 минуты
</p>

---

## Что проверяет AuditGuard

| Направление | Что анализируем | Стандарты |
|-------------|----------------|-----------|
| 🔒 Security Headers | CSP, HSTS, X-Frame-Options, Permissions-Policy | OWASP, CIS |
| 🔐 TLS/SSL | Версия, шифры, цепочка, expiry, CT logs | NIST SP 800-52 |
| 🌐 DNS | SPF, DKIM, DMARC, CAA, NS конфигурация | RFC 7489, RFC 8659 |
| 🛡️ CVE / Vulnerabilities | NVD, EPSS, CISA KEV, Shodan InternetDB | CVSSv3, BOD 22-01 |
| 🔍 Shodan InternetDB | Открытые порты, баннеры, reputation | Shodan |
| 🌍 SEO & Visibility | Meta, canonical, robots.txt, sitemap | Google Guidelines |
| 🤖 AI / GEO | Llms.txt, AI-crawler policy, structured data | Emerging standards |
| 🔗 Third-party | Внешние скрипты, CDN, зависимости | OWASP A08 |
| 📊 Performance | Core Web Vitals baseline, TTFB, resource hints | CWV |

## Быстрый старт

### curl
```bash
# Запустить аудит
curl -X POST https://auditguard.ru/api/audits \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Получить результат (auditId из предыдущего запроса)
curl https://auditguard.ru/api/audits/{auditId}
```

### Python
```bash
pip install requests
```
```python
from auditguard import AuditGuard

client = AuditGuard()
report = client.audit("https://example.com")

print(f"Trust Grade: {report.grade}")
print(f"Score: {report.score}/100")

for f in report.critical_findings:
    print(f"[{f.severity}] {f.category}: {f.title}")
```

### JavaScript / Node.js
```bash
npm install auditguard
```
```javascript
import { AuditGuard } from 'auditguard';

const client = new AuditGuard();
const report = await client.audit('https://example.com');

console.log(`Trust Grade: ${report.grade}`);
report.findings
  .filter(f => f.severity === 'critical')
  .forEach(f => console.log(`[${f.category}] ${f.title}`));
```

## API Reference

### POST /api/audits — Запуск аудита
```http
POST https://auditguard.ru/api/audits
Content-Type: application/json

{
  "url": "https://example.com",
  "profile": "technical_first"
}
```

**Ответ:**
```json
{
  "id": "uuid-v4",
  "status": "queued",
  "url": "https://example.com"
}
```

### GET /api/audits/:id — Получение результата
```http
GET https://auditguard.ru/api/audits/{id}
```

**Ответ (завершённый аудит):**
```json
{
  "id": "uuid-v4",
  "url": "https://example.com",
  "grade": "B",
  "score": 68,
  "findings": [
    {
      "id": "tls-1",
      "category": "tls",
      "severity": "high",
      "title": "TLS 1.0/1.1 включены — устаревшие протоколы",
      "where": "https://example.com",
      "whyRisk": "TLS 1.0/1.1 содержат известные уязвимости (POODLE, BEAST)...",
      "fix": "Отключите TLS 1.0 и 1.1, оставьте только TLS 1.2 и 1.3...",
      "confidence": 0.99
    },
    {
      "id": "cve-shodan-1",
      "category": "cve",
      "severity": "high",
      "title": "CVE-2023-XXXX обнаружен в Shodan InternetDB",
      "where": "93.184.216.34",
      "whyRisk": "EPSS: 67%... ⚠️ Наличие CVE не подтверждает факт компрометации — требует ручной проверки.",
      "fix": "Обновите компонент до версии...",
      "confidence": 0.75,
      "interpretationNote": "CVE ≠ компрометация. Требуется ручная проверка: запустите ли вы уязвимый компонент на этом IP?"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 3
  },
  "checkedAt": "2026-06-05T09:00:00Z"
}
```

### Trust Grade

| Grade | Score | Значение |
|-------|-------|---------|
| A+ | 95–100 | Образцовая безопасность |
| A | 85–94 | Хороший уровень |
| B | 70–84 | Требует внимания |
| C | 50–69 | Серьёзные пробелы |
| D | 25–49 | Критические уязвимости |
| ❗ | 0–24 | Критический уровень риска |

## Severity уровни

| Severity | Значение |
|----------|---------|
| `critical` | Активно эксплуатируемая уязвимость или немедленный риск |
| `high` | Значимая уязвимость, требует приоритетного исправления |
| `medium` | Рекомендуемое исправление, не критично срочно |
| `low` | Незначительное замечание или лучшая практика |

## CVE и interpretationNote

AuditGuard использует данные **NVD**, **EPSS**, **CISA KEV** и **Shodan InternetDB** для выявления CVE-уязвимостей. Каждая CVE-находка содержит `interpretationNote`:

> ⚠️ **Наличие CVE не подтверждает факт компрометации** — требует ручной проверки.

Приоритизация CVE:
- **CISA KEV** — активно эксплуатируемые уязвимости (BOD 22-01)
- **EPSS ≥ 50%** — высокая вероятность эксплойта в ближайшие 30 дней
- **Shodan InternetDB** — CVE по IP-адресу сервера

## GitHub Actions — автоматический аудит в CI/CD

```yaml
# .github/workflows/security-audit.yml
name: Security Audit

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 9 * * 1'  # Каждый понедельник 9:00

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Run AuditGuard Audit
        uses: Gudvin82/auditguard@v1
        with:
          url: ${{ vars.SITE_URL }}
          fail_on_critical: true
```

## SARIF Export

AuditGuard поддерживает экспорт результатов в **SARIF 2.1.0** для интеграции с GitHub Security:

```bash
curl https://auditguard.ru/api/audits/{auditId}/sarif \
  -H "Accept: application/sarif+json" > results.sarif
```

```yaml
# В GitHub Actions — загрузка в Security tab
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Use Cases

- **DevSecOps команды** — security gate перед деплоем
- **Пентестеры** — быстрый внешний скан поверхности атаки
- **SRE/Ops** — регулярный мониторинг безопасности
- **Bug Bounty** — первичная разведка поверхности атаки
- **CTO/CISO** — executive-level security posture overview

## Методология

Подробнее: [auditguard.ru/methodology](https://auditguard.ru/methodology)

- **46+ инструментов** — Shodan, EPSS API, CISA KEV, AlienVault OTX, AbuseIPDB, SSL Labs, crt.sh, Google Safe Browsing
- **CVE приоритизация** — CVSS v3 + EPSS + CISA KEV + Shodan InternetDB
- **SARIF 2.1.0** — экспорт для GitHub Security / SIEM
- **AI-слой** — контекстный анализ с audit trail

## Лицензия

Apache License 2.0 — клиентский код открыт. Движок работает как облачный сервис.

---

<p align="center">
  <a href="https://auditguard.ru">🌐 Запустить аудит</a> ·
  <a href="https://auditguard.ru/methodology">📖 Методология</a> ·
  <a href="https://auditguard.ru/faq">❓ FAQ</a>
</p>
