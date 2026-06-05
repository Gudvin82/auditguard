"""
AuditGuard Python Client
https://auditguard.ru
"""

import time
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

BASE_URL = "https://auditguard.ru/api"
DEFAULT_TIMEOUT = 30
POLL_INTERVAL = 5
MAX_WAIT = 300


@dataclass
class AuditGuardFinding:
    id: str
    category: str
    severity: str  # critical | high | medium | low
    title: str
    where: str
    why_risk: str = ""
    fix: str = ""
    confidence: float = 1.0
    interpretation_note: str = ""  # CVE interpretationNote
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "AuditGuardFinding":
        return cls(
            id=data.get("id", ""),
            category=data.get("category", ""),
            severity=data.get("severity", "medium"),
            title=data.get("title", ""),
            where=data.get("where", ""),
            why_risk=data.get("whyRisk", ""),
            fix=data.get("fix", ""),
            confidence=data.get("confidence", 1.0),
            interpretation_note=data.get("interpretationNote", ""),
            raw=data,
        )

    @property
    def is_cve(self) -> bool:
        return self.category in ("cve", "shodan", "epss", "kev")


@dataclass
class AuditGuardReport:
    id: str
    url: str
    grade: str
    score: int
    findings: List[AuditGuardFinding]
    summary: Dict[str, int]
    checked_at: str
    ai_review_log: List[Dict] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def critical_findings(self) -> List[AuditGuardFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> List[AuditGuardFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def cve_findings(self) -> List[AuditGuardFinding]:
        return [f for f in self.findings if f.is_cve]

    def findings_by_category(self, category: str) -> List[AuditGuardFinding]:
        return [f for f in self.findings if f.category == category]

    @classmethod
    def from_dict(cls, data: dict) -> "AuditGuardReport":
        return cls(
            id=data.get("id", ""),
            url=data.get("url", ""),
            grade=data.get("grade", "?"),
            score=data.get("score", 0),
            findings=[AuditGuardFinding.from_dict(f) for f in data.get("findings", [])],
            summary=data.get("summary", {}),
            checked_at=data.get("checkedAt", ""),
            ai_review_log=data.get("aiReviewLog", []),
            raw=data,
        )


class AuditGuardError(Exception):
    pass


class AuditGuard:
    """
    Клиент API AuditGuard — технический и кибербезопасность-аудит сайтов.

    Пример:
        client = AuditGuard()
        report = client.audit("https://example.com")
        print(f"Grade: {report.grade}, Score: {report.score}")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        if api_key:
            self._session.headers.update({"Authorization": f"Bearer {api_key}"})

    def start_audit(self, url: str, profile: str = "technical_first") -> str:
        """Запустить аудит. Возвращает audit ID."""
        resp = self._session.post(
            f"{self.base_url}/audits",
            json={"url": url, "profile": profile},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["id"]

    def get_audit(self, audit_id: str) -> Dict[str, Any]:
        """Получить результат аудита по ID."""
        resp = self._session.get(
            f"{self.base_url}/audits/{audit_id}",
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_sarif(self, audit_id: str) -> Dict[str, Any]:
        """Получить результат в формате SARIF 2.1.0."""
        resp = self._session.get(
            f"{self.base_url}/audits/{audit_id}/sarif",
            headers={"Accept": "application/sarif+json"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def audit(
        self,
        url: str,
        profile: str = "technical_first",
        poll_interval: int = POLL_INTERVAL,
        max_wait: int = MAX_WAIT,
    ) -> AuditGuardReport:
        """
        Запустить аудит и дождаться результата.

        Args:
            url: URL сайта для проверки
            profile: профиль аудита (technical_first / legal_first)
            poll_interval: интервал опроса в секундах
            max_wait: максимальное время ожидания в секундах

        Returns:
            AuditGuardReport с результатами аудита
        """
        audit_id = self.start_audit(url, profile)
        start = time.time()

        while True:
            elapsed = time.time() - start
            if elapsed > max_wait:
                raise AuditGuardError(
                    f"Таймаут ожидания аудита {audit_id} после {max_wait}с"
                )

            data = self.get_audit(audit_id)
            status = data.get("status")

            if status == "completed":
                return AuditGuardReport.from_dict(data)
            elif status == "failed":
                raise AuditGuardError(
                    f"Аудит {audit_id} завершился с ошибкой: {data.get('error', 'unknown')}"
                )

            time.sleep(poll_interval)
