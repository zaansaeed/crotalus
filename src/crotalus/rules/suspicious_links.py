"""Project links pointing somewhere legitimate projects don't.

Honest packages link GitHub, GitLab or their docs. Raw IP addresses, URL
shorteners, chat invites and paste sites hide where you end up, and show up in
malware that wants to look "linked" or sends people somewhere else.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from crotalus.models import AnalysisContext, Finding

# Matched against the host and its parent domains, so "cdn.discord.com" counts too.
SUSPICIOUS_DOMAINS = {
    "bit.ly": "URL shortener",
    "tinyurl.com": "URL shortener",
    "t.co": "URL shortener",
    "is.gd": "URL shortener",
    "discord.gg": "chat invite",
    "discord.com": "chat invite",
    "t.me": "chat invite",
    "pastebin.com": "paste site",
    "rentry.co": "paste site",
    "hastebin.com": "paste site",
}


def link_problem(url: str) -> str | None:
    """Why this link is suspicious, or None if it looks fine."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return f"unusual scheme '{parts.scheme}'"

    host = (parts.hostname or "").lower()
    if not host:
        return "no host"
    try:
        ipaddress.ip_address(host)
        return "raw IP address"
    except ValueError:
        pass  # not an IP, a normal hostname

    # "a.b.example.com" -> check "a.b.example.com", "b.example.com", "example.com", "com"
    labels = host.split(".")
    for i in range(len(labels)):
        reason = SUSPICIOUS_DOMAINS.get(".".join(labels[i:]))
        if reason:
            return reason
    return None


def check(context: AnalysisContext) -> list[Finding]:
    flagged = []
    for label, url in context.metadata.project_urls.items():
        reason = link_problem(url)
        if reason:
            flagged.append({"label": label, "url": url, "reason": reason})
    if not flagged: #clean
        return []

    reasons = ", ".join(sorted({f["reason"] for f in flagged}))
    return [
        Finding(
            rule_id="suspicious_links",
            severity="medium",
            message=f"project links point to suspicious places ({reasons})",
            evidence={"links": flagged},
        )
    ]
