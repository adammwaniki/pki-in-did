"""Rendering a verification for a person watching a screen.

Deliberately wide-margined and high-contrast: this output is the subject of a video, so it
has to stay legible when scaled down.
"""

from __future__ import annotations

import os
import shutil

from .store import sha256_fingerprint

MARKS = {"pass": "PASS", "fail": "FAIL", "skip": "skip", "not-run": "  · "}


def _colour(enabled: bool):
    if not enabled:
        return lambda text, _name: text
    codes = {"green": "32", "red": "31", "grey": "90", "bold": "1", "yellow": "33"}
    return lambda text, name: f"\033[{codes[name]}m{text}\033[0m"


def render_text(result, *, colour: bool | None = None) -> str:
    if colour is None:
        colour = os.environ.get("NO_COLOR") is None and os.isatty(1) if hasattr(os, "isatty") else False
    paint = _colour(colour)
    width = min(shutil.get_terminal_size((100, 24)).columns, 100)
    rule = "─" * width
    lines: list[str] = []

    parsed = result.credential
    lines.append(rule)
    lines.append(paint("  Verifying a credential against the National Root CA", "bold"))
    lines.append(rule)
    if parsed:
        lines.append(f"  issuer         {parsed.issuer}")
        lines.append(f"  key reference  {parsed.key_reference}")
        lines.append(f"  credential     {', '.join(parsed.types) or '—'}  [{parsed.form}, {parsed.alg}]")
    lines.append(f"  network        {'none (offline)' if result.offline else 'available'}")
    lines.append("")

    for check in result.checks:
        mark = MARKS.get(check.status, check.status)
        if check.status == "pass":
            mark = paint(mark, "green")
        elif check.status == "fail":
            mark = paint(mark, "red")
        elif check.status in ("skip", "not-run"):
            mark = paint(mark, "grey")
        title = check.title if check.status != "not-run" else paint(check.title, "grey")
        lines.append(f"  {check.number:>2}. [{mark}] {title}")
        lines.append(f"        {paint(check.key, 'grey')}  {check.detail}" if check.detail
                     else f"        {paint(check.key, 'grey')}")

    lines.append("")
    if result.path:
        lines.append(f"  trust anchor   {_cn(result.path.anchor)}")
        lines.append(f"  fingerprint    {sha256_fingerprint(result.path.anchor)}")
        lines.append(f"  path           {result.path.describe()}")
    if result.revocation:
        rev = result.revocation
        source = rev.source or "—"
        lines.append(f"  revocation     {(rev.method or '—').upper()} {rev.status} "
                     f"(from {source}{', ' + rev.reason if rev.reason else ''})")
        if rev.next_update:
            lines.append(f"  fresh until    {rev.next_update.isoformat().replace('+00:00', 'Z')}")
    lines.append("")

    if result.accepted:
        lines.append(paint("  ACCEPTED", "green") + "  every check passed")
    else:
        failed = result.failed_check
        lines.append(paint("  REJECTED", "red")
                     + f"  {result.reason}"
                     + (f" (check {failed.number}, {failed.key})" if failed else ""))
        if failed and failed.detail:
            lines.append(f"            {failed.detail}")
    lines.append(rule)
    return "\n".join(lines)


def _cn(cert) -> str:
    from cryptography.x509.oid import NameOID

    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else cert.subject.rfc4514_string()
