import asyncio
import httpx
from ..models import Finding, Severity

_CONCURRENCY = 10


async def probe_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
    endpoints: list[str],
    finding_counter: list[int],
    progress_callback=None,
) -> list[Finding]:
    base = base_url.rstrip("/")
    sem = asyncio.Semaphore(_CONCURRENCY)
    done = [0]
    total = len(endpoints)

    async def probe(raw: str) -> Finding | None:
        parts = raw.split(" ", 1)
        method, path = (parts[0], parts[1]) if len(parts) == 2 else ("GET", parts[0])
        url = base + path

        try:
            async with sem:
                resp = await client.request(method, url, follow_redirects=False)
        except httpx.RequestError:
            done[0] += 1
            if progress_callback:
                progress_callback(done[0], total)
            return None

        done[0] += 1
        if progress_callback:
            progress_callback(done[0], total)

        if resp.status_code == 401 and "www-authenticate" not in resp.headers:
            finding_counter[0] += 1
            return Finding(
                id=f"LIVE-{finding_counter[0]:03d}",
                severity=Severity.LOW,
                module="live",
                endpoint=f"{method} {path}",
                title="401 Without WWW-Authenticate Header",
                detail="Endpoint returns 401 but omits the WWW-Authenticate header, violating RFC 7235.",
                remediation="Include a proper WWW-Authenticate challenge in 401 responses.",
                evidence="HTTP 401, no WWW-Authenticate",
            )

        if resp.status_code >= 500:
            body_preview = resp.text[:300]
            if any(kw in body_preview.lower() for kw in ("traceback", "exception", "stack", "at line", "sqlexception", "syntax error")):
                finding_counter[0] += 1
                return Finding(
                    id=f"LIVE-{finding_counter[0]:03d}",
                    severity=Severity.HIGH,
                    module="live",
                    endpoint=f"{method} {path}",
                    title="Verbose Error / Stack Trace Leaked",
                    detail=f"Server returned HTTP {resp.status_code} with what appears to be a raw stack trace or exception.",
                    remediation="Return generic error messages in production. Log details server-side.",
                    evidence=body_preview[:150] + "…",
                )

        path_lower = path.lower()
        if resp.status_code == 200 and any(k in path_lower for k in ("/admin", "/internal", "/debug", "/secret", "/private")):
            finding_counter[0] += 1
            return Finding(
                id=f"LIVE-{finding_counter[0]:03d}",
                severity=Severity.CRITICAL,
                module="live",
                endpoint=f"{method} {path}",
                title="Admin/Internal Path Accessible Without Auth",
                detail=f"`{method} {path}` returned HTTP 200 without any authentication.",
                remediation="Require authentication (and authorisation) before serving this path.",
                evidence=f"HTTP 200 — {len(resp.content)} bytes",
            )

        return None

    results = await asyncio.gather(*[probe(ep) for ep in endpoints])
    return [r for r in results if r is not None]
