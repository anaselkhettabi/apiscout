import httpx
from ..models import Finding, Severity

# Common sensitive/debug paths worth probing
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

JUICY_CONTENT_TYPES = {
    "application/json", "text/plain", "application/yaml",
    "application/x-yaml", "text/yaml",
}


async def fuzz_paths(
    client: httpx.AsyncClient,
    base_url: str,
    finding_counter: list[int],
    progress_callback=None,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    discovered: list[str] = []

    base = base_url.rstrip("/")

    for i, path in enumerate(WORDLIST):
        url = base + path
        try:
            resp = await client.get(url, follow_redirects=False)
        except httpx.RequestError:
            if progress_callback:
                progress_callback(i + 1, len(WORDLIST))
            continue

        if progress_callback:
            progress_callback(i + 1, len(WORDLIST))

        if resp.status_code in (200, 201, 204):
            discovered.append(url)
            ct = resp.headers.get("content-type", "").split(";")[0].strip()

            if path in SENSITIVE_PATHS:
                finding_counter[0] += 1
                findings.append(
                    Finding(
                        id=f"FUZ-{finding_counter[0]:03d}",
                        severity=Severity.CRITICAL,
                        module="fuzzer",
                        endpoint=path,
                        title=f"Sensitive Path Exposed: {path}",
                        detail=f"Received HTTP {resp.status_code} from `{url}`. This path should never be publicly reachable.",
                        remediation="Block this path at the gateway/web server level.",
                        evidence=f"HTTP {resp.status_code} — {len(resp.content)} bytes",
                    )
                )
            elif path in ("/swagger.json", "/openapi.json", "/api-docs", "/api-docs.json"):
                finding_counter[0] += 1
                findings.append(
                    Finding(
                        id=f"FUZ-{finding_counter[0]:03d}",
                        severity=Severity.MEDIUM,
                        module="fuzzer",
                        endpoint=path,
                        title="API Spec Publicly Accessible",
                        detail=f"`{path}` is accessible without authentication ({resp.status_code}).",
                        remediation="Restrict spec access to authenticated/internal users in production.",
                        evidence=f"HTTP {resp.status_code}",
                    )
                )
            elif path.startswith("/actuator"):
                finding_counter[0] += 1
                findings.append(
                    Finding(
                        id=f"FUZ-{finding_counter[0]:03d}",
                        severity=Severity.HIGH,
                        module="fuzzer",
                        endpoint=path,
                        title=f"Spring Actuator Endpoint Exposed: {path}",
                        detail="Actuator endpoints can leak environment variables, bean configs, and heap dumps.",
                        remediation="Disable or restrict actuator endpoints via management.endpoints.web.exposure.include.",
                        evidence=f"HTTP {resp.status_code}",
                    )
                )

        elif resp.status_code == 403:
            # Exists but blocked — still interesting
            if path in SENSITIVE_PATHS:
                finding_counter[0] += 1
                findings.append(
                    Finding(
                        id=f"FUZ-{finding_counter[0]:03d}",
                        severity=Severity.LOW,
                        module="fuzzer",
                        endpoint=path,
                        title=f"Sensitive Path Exists (Forbidden): {path}",
                        detail=f"`{path}` returns 403 — it exists but access is currently blocked. Verify this is intentional.",
                        remediation="Confirm the path is properly protected and consider returning 404 instead of 403.",
                        evidence="HTTP 403",
                    )
                )

    return findings, discovered
