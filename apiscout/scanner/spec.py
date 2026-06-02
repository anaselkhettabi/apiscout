import json
import yaml
import httpx
from pathlib import Path
from ..models import Finding, Severity


async def _load_spec(client: httpx.AsyncClient, source: str) -> dict | None:
    if source.startswith("http://") or source.startswith("https://"):
        try:
            resp = await client.get(source, follow_redirects=True)
            resp.raise_for_status()
            try:
                return resp.json()
            except Exception:
                return yaml.safe_load(resp.text)
        except Exception:
            return None
    else:
        p = Path(source)
        if not p.exists():
            return None
        text = p.read_text(encoding="utf-8")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return yaml.safe_load(text)


def _iter_paths(spec: dict) -> list[tuple[str, str, dict]]:
    results = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "head", "options"):
                results.append((path, method.upper(), op))
    return results


def _has_security(op: dict, global_security: list) -> bool:
    if "security" in op:
        return bool(op["security"])
    return bool(global_security)


async def analyze_spec(
    client: httpx.AsyncClient,
    source: str,
    finding_counter: list[int],
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    spec = await _load_spec(client, source)

    if spec is None:
        return findings, []

    global_security = spec.get("security", [])
    paths_obj = spec.get("paths", {})
    endpoints = [m.upper() + " " + p for p, methods in paths_obj.items() for m in methods if m.lower() not in ("parameters", "summary", "description")]

    for path, method, op in _iter_paths(spec):
        endpoint_label = f"{method} {path}"

        if method in ("POST", "PUT", "PATCH", "DELETE") and not _has_security(op, global_security):
            finding_counter[0] += 1
            findings.append(
                Finding(
                    id=f"SPEC-{finding_counter[0]:03d}",
                    severity=Severity.HIGH,
                    module="spec",
                    endpoint=endpoint_label,
                    title="No Authentication Defined for Mutating Endpoint",
                    detail=f"`{endpoint_label}` has no security scheme defined in the spec.",
                    remediation="Add a security requirement object to this operation or globally.",
                )
            )

        if method == "GET" and not _has_security(op, global_security):
            path_lower = path.lower()
            if any(k in path_lower for k in ("/user", "/account", "/profile", "/admin", "/secret", "/token", "/key")):
                finding_counter[0] += 1
                findings.append(
                    Finding(
                        id=f"SPEC-{finding_counter[0]:03d}",
                        severity=Severity.MEDIUM,
                        module="spec",
                        endpoint=endpoint_label,
                        title="Potentially Sensitive GET Endpoint Unauthenticated",
                        detail=f"`{endpoint_label}` appears to return user/account data but has no auth requirement.",
                        remediation="Verify whether this endpoint should require authentication.",
                    )
                )

        if op.get("deprecated", False):
            finding_counter[0] += 1
            findings.append(
                Finding(
                    id=f"SPEC-{finding_counter[0]:03d}",
                    severity=Severity.INFO,
                    module="spec",
                    endpoint=endpoint_label,
                    title="Deprecated Endpoint Still in Spec",
                    detail=f"`{endpoint_label}` is marked deprecated but still present in the spec.",
                    remediation="Remove deprecated endpoints once clients have migrated.",
                )
            )

        for param in op.get("parameters", []):
            if "schema" not in param and "content" not in param:
                finding_counter[0] += 1
                findings.append(
                    Finding(
                        id=f"SPEC-{finding_counter[0]:03d}",
                        severity=Severity.LOW,
                        module="spec",
                        endpoint=endpoint_label,
                        title=f"Parameter `{param.get('name', '?')}` Missing Schema",
                        detail="No input validation schema defined — may allow unexpected input types.",
                        remediation="Add schema constraints (type, format, maxLength, pattern) to all parameters.",
                    )
                )

    if not spec.get("components", {}).get("securitySchemes") and not spec.get("securityDefinitions"):
        finding_counter[0] += 1
        findings.append(
            Finding(
                id=f"SPEC-{finding_counter[0]:03d}",
                severity=Severity.HIGH,
                module="spec",
                endpoint="*",
                title="No Security Schemes Defined in Spec",
                detail="The spec defines no security schemes (Bearer, OAuth2, API key, etc.).",
                remediation="Define at least one security scheme in `components.securitySchemes`.",
            )
        )

    return findings, endpoints
