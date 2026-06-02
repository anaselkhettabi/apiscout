import asyncio
import httpx
from ..models import Finding, Severity

WORDLIST = [
    # Docs & specs
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/docs", "/redoc",
    # Admin / debug
    "/admin", "/admin/", "/administrator", "/dashboard",
    "/debug", "/debug/vars", "/health", "/healthz", "/ping",
    "/metrics", "/prometheus", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    # Auth
    "/login", "/auth", "/token", "/oauth/token",
    # Internal / legacy
    "/v1", "/v2", "/v3", "/api/v1", "/api/v2",
    "/internal", "/private", "/secret",
    "/backup", "/config", "/.env", "/.git/HEAD",
    "/server-status", "/server-info",
    # GraphQL
    "/graphql", "/graphiql", "/playground",
]

SENSITIVE_PATHS = {
    "/.env", "/.git/HEAD", "/backup", "/config",
    "/actuator/env", "/actuator/beans", "/server-status",
}

_CONCURRENCY = 10


async def fuzz_paths(
    client: httpx.AsyncClient,
    base_url: str,
    finding_counter: list[int],
    progress_callback=None,
) -> tuple[list[Finding], list[str]]:
    base = base_url.rstrip("/")
    sem = asyncio.Semaphore(_CONCURRENCY)
    done = [0]
    total = len(WORDLIST)

    async def probe(path: str) -> tuple[Finding | None, str | None]:
        url = base + path
        try:
            async with sem:
                resp = await client.get(url, follow_redirects=False)
        except httpx.RequestError:
            done[0] += 1
            if progress_callback:
                progress_callback(done[0], total)
            return None, None

        done[0] += 1
        if progress_callback:
            progress_callback(done[0], total)

        finding: Finding | None = None
        discovered: str | None = None

        if resp.status_code in (200, 201, 204):
            discovered = url
            if path in SENSITIVE_PATHS:
                finding_counter[0] += 1
                finding = Finding(
                    id=f"FUZ-{finding_counter[0]:03d}",
                    severity=Severity.CRITICAL,
                    module="fuzzer",
                    endpoint=path,
                    title=f"Sensitive Path Exposed: {path}",
                    detail=f"Received HTTP {resp.status_code} from `{url}`. This path should never be publicly reachable.",
                    remediation="Block this path at the gateway/web server level.",
                    evidence=f"HTTP {resp.status_code} — {len(resp.content)} bytes",
                )
            elif path in ("/swagger.json", "/openapi.json", "/api-docs", "/api-docs.json"):
                finding_counter[0] += 1
                finding = Finding(
                    id=f"FUZ-{finding_counter[0]:03d}",
                    severity=Severity.MEDIUM,
                    module="fuzzer",
                    endpoint=path,
                    title="API Spec Publicly Accessible",
                    detail=f"`{path}` is accessible without authentication ({resp.status_code}).",
                    remediation="Restrict spec access to authenticated/internal users in production.",
                    evidence=f"HTTP {resp.status_code}",
                )
            elif path.startswith("/actuator"):
                finding_counter[0] += 1
                finding = Finding(
                    id=f"FUZ-{finding_counter[0]:03d}",
                    severity=Severity.HIGH,
                    module="fuzzer",
                    endpoint=path,
                    title=f"Spring Actuator Endpoint Exposed: {path}",
                    detail="Actuator endpoints can leak environment variables, bean configs, and heap dumps.",
                    remediation="Disable or restrict actuator endpoints via management.endpoints.web.exposure.include.",
                    evidence=f"HTTP {resp.status_code}",
                )

        elif resp.status_code == 403 and path in SENSITIVE_PATHS:
            finding_counter[0] += 1
            finding = Finding(
                id=f"FUZ-{finding_counter[0]:03d}",
                severity=Severity.LOW,
                module="fuzzer",
                endpoint=path,
                title=f"Sensitive Path Exists (Forbidden): {path}",
                detail=f"`{path}` returns 403 — it exists but access is currently blocked. Verify this is intentional.",
                remediation="Confirm the path is properly protected and consider returning 404 instead of 403.",
                evidence="HTTP 403",
            )

        return finding, discovered

    results = await asyncio.gather(*[probe(p) for p in WORDLIST])
    findings = [r[0] for r in results if r[0] is not None]
    discovered = [r[1] for r in results if r[1] is not None]
    return findings, discovered
