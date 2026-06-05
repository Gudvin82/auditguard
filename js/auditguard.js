/**
 * AuditGuard JavaScript/Node.js Client
 * Официальный клиент для API технического аудита
 * https://auditguard.ru
 *
 * @license Apache-2.0
 */

const BASE_URL = 'https://auditguard.ru/api';
const DEFAULT_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 5_000;
const MAX_WAIT_MS = 300_000;

export class AuditGuardFinding {
  constructor(data) {
    this.id = data.id ?? '';
    this.category = data.category ?? '';
    this.severity = data.severity ?? 'medium';
    this.title = data.title ?? '';
    this.where = data.where ?? '';
    this.whyRisk = data.whyRisk ?? '';
    this.fix = data.fix ?? '';
    this.confidence = data.confidence ?? 1.0;
    this.interpretationNote = data.interpretationNote ?? '';
    this.raw = data;
  }

  get isCve() {
    return ['cve', 'shodan', 'epss', 'kev'].includes(this.category);
  }
}

export class AuditGuardReport {
  constructor(data) {
    this.id = data.id ?? '';
    this.url = data.url ?? '';
    this.grade = data.grade ?? '?';
    this.score = data.score ?? 0;
    this.findings = (data.findings ?? []).map(f => new AuditGuardFinding(f));
    this.summary = data.summary ?? {};
    this.checkedAt = data.checkedAt ?? '';
    this.aiReviewLog = data.aiReviewLog ?? [];
    this.raw = data;
  }

  get criticalFindings() {
    return this.findings.filter(f => f.severity === 'critical');
  }

  get highFindings() {
    return this.findings.filter(f => f.severity === 'high');
  }

  get cveFindings() {
    return this.findings.filter(f => f.isCve);
  }

  get totalFindings() {
    return this.findings.length;
  }

  findingsByCategory(category) {
    return this.findings.filter(f => f.category === category);
  }
}

export class AuditGuardError extends Error {
  constructor(message, statusCode = null) {
    super(message);
    this.name = 'AuditGuardError';
    this.statusCode = statusCode;
  }
}

export class AuditGuard {
  constructor({ apiKey, baseUrl, timeoutMs } = {}) {
    this.apiKey = apiKey ?? null;
    this.baseUrl = (baseUrl ?? BASE_URL).replace(/\/$/, '');
    this.timeoutMs = timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  _headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this.apiKey) h['Authorization'] = `Bearer ${this.apiKey}`;
    return h;
  }

  async _fetch(path, options = {}) {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(url, {
        ...options,
        headers: { ...this._headers(), ...(options.headers ?? {}) },
        signal: controller.signal,
      });

      if (!res.ok) {
        let body = '';
        try { body = await res.text(); } catch (_) {}
        throw new AuditGuardError(`HTTP ${res.status}: ${body.slice(0, 200)}`, res.status);
      }

      return res.json();
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new AuditGuardError(`Таймаут запроса (${this.timeoutMs}мс)`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  async startAudit(url, profile = 'technical_first') {
    const data = await this._fetch('/audits', {
      method: 'POST',
      body: JSON.stringify({ url, profile }),
    });
    return data.id;
  }

  async getAudit(auditId) {
    return this._fetch(`/audits/${auditId}`);
  }

  async getSarif(auditId) {
    return this._fetch(`/audits/${auditId}/sarif`, {
      headers: { Accept: 'application/sarif+json' },
    });
  }

  async audit(url, { profile = 'technical_first', pollMs = POLL_INTERVAL_MS, maxWaitMs = MAX_WAIT_MS, onProgress } = {}) {
    const auditId = await this.startAudit(url, profile);
    const start = Date.now();

    while (true) {
      const elapsed = Date.now() - start;
      if (elapsed > maxWaitMs) {
        throw new AuditGuardError(`Таймаут ожидания аудита ${auditId} (${maxWaitMs / 1000}с)`);
      }

      const data = await this.getAudit(auditId);
      const { status } = data;

      if (onProgress) onProgress(status, elapsed);

      if (status === 'completed') return new AuditGuardReport(data);
      if (status === 'failed') throw new AuditGuardError(`Аудит ${auditId} завершился с ошибкой: ${data.error ?? 'unknown'}`);

      await new Promise(r => setTimeout(r, pollMs));
    }
  }
}

export default AuditGuard;
