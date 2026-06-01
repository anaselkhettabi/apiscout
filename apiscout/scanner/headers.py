import httpx
from ..models import Finding, Severity

SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.HIGH,
        "Missing HSTS Header",
        "Clients can be downgraded to HTTP. Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing X-Content-Type-Options",
        "Browsers may MIME-sniff responses. Add `X-Content-Type-Options: nosniff`.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Missing X-Frame-Options",
        "Endpoint may be embeddable in iframes (clickjacking). Add `X-Frame-Options: DENY`.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Missing Content-Security-Policy",
        "No CSP header found. Define a restrictive CSP to limit XSS impact.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Missing Permissions-Policy",
        "Consider adding a Permissions-Policy header to restrict browser feature access.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Missing Referrer-Policy",
        "Add `Referrer-Policy: strict-origin-when-cross-origin` to control referrer leakage.",
    ),
}

DANGEROUS_HEADERS = {
    "server": (
        Severity.INFO,
        "Server Banner Disclosed",
        "The `Server` header reveals implementation details. Strip or genericise it.",
    ),
    "x-powered-by": (
        Severity.LOW,
        "X-Powered-By Disclosed",
        "Remove the `X-Powered-By` header to reduce fingerprinting surface.",
    ),
    "x-aspnet-version": (
        Severity.LOW,
        "ASP.NET Version Disclosed",
        "Remove `X-AspNet-Version` — it reveals exact runtime version.",
    ),
}


async def check_headers(
    client: httpx.AsyncClient,
    target: str,
    finding_counter: list[int],
) -> list[Finding]:
    findings: list[Finding] = []

    try:
        resp = await client.get(target, follow_redirects=True)
    except httpx.RequestError:
        return findings

    present = {k.lower() for k in resp.headers.keys()}

    for header, (severity, title, remediation) in SECURITY_HEADERS.items():
        if header not in present:
            finding_counter[0] += 1
            findings.append(
                Finding(
                    id=f"HDR-{finding_counter[0]:03d}",
                    severity=severity,
                    module="headers",
                    endpoint="*",
                    title=title,
                    detail=f"The `{header}` header was not present in the response.",
                    remediation=remediation,
                )
            )

    for header, (severity, title, remediation) in DANGEROUS_HEADERS.items():
        if header in present:
            finding_counter[0] += 1
            findings.append(
                Finding(
                    id=f"HDR-{finding_counter[0]:03d}",
                    severity=severity,
                    module="headers",
                    endpoint="*",
                    title=title,
                    detail=f"Response includes `{header}: {resp.headers.get(header)}`.",
                    remediation=remediation,
                    evidence=f"{header}: {resp.headers.get(header)}",
                )
            )

    # CORS check
    origin_test = dict(resp.headers)
    acao = origin_test.get("access-control-allow-origin", "")
    if acao == "*":
        finding_counter[0] += 1
        findings.append(
            Finding(
                id=f"HDR-{finding_counter[0]:03d}",
                severity=Severity.HIGH,
                module="headers",
                endpoint="*",
                title="Wildcard CORS Policy",
                detail="Access-Control-Allow-Origin: * allows any origin to read responses.",
                remediation="Restrict CORS to trusted origins explicitly.",
                evidence="Access-Control-Allow-Origin: *",
            )
        )

    return findings
