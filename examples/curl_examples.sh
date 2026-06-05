#!/usr/bin/env bash
# AuditGuard — примеры curl
# https://auditguard.ru

BASE="https://auditguard.ru/api"

# ──────────────────────────────────────────────
# 1. Запустить аудит
# ──────────────────────────────────────────────
echo "=== Запуск аудита ==="
RESPONSE=$(curl -s -X POST "$BASE/audits" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "profile": "technical_first"}')

echo "$RESPONSE"
AUDIT_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "Audit ID: $AUDIT_ID"


# ──────────────────────────────────────────────
# 2. Polling до завершения
# ──────────────────────────────────────────────
echo -e "\n=== Ожидание результата ==="
for i in $(seq 1 60); do
  sleep 5
  RESULT=$(curl -s "$BASE/audits/$AUDIT_ID")
  STATUS=$(echo "$RESULT" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
  echo "  ($i) status: $STATUS"
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
done


# ──────────────────────────────────────────────
# 3. Вывести результат
# ──────────────────────────────────────────────
echo -e "\n=== Результат ==="
echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'Grade: {d.get(\"grade\",\"?\")}  Score: {d.get(\"score\",0)}')
s = d.get('summary', {})
print(f'Findings: critical={s.get(\"critical\",0)}, high={s.get(\"high\",0)}, medium={s.get(\"medium\",0)}, low={s.get(\"low\",0)}')
for f in d.get('findings',[])[:5]:
    note = '  ⚠️ ' + f['interpretationNote'] if f.get('interpretationNote') else ''
    print(f'  [{f[\"severity\"]}] {f[\"category\"]}: {f[\"title\"]}{note}')
"


# ──────────────────────────────────────────────
# 4. Получить SARIF 2.1.0
# ──────────────────────────────────────────────
# curl -s "$BASE/audits/$AUDIT_ID/sarif" \
#   -H "Accept: application/sarif+json" > results.sarif
# echo "SARIF saved to results.sarif"
