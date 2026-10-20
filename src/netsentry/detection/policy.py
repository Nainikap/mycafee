"""User decisions (allow / deny / mute) applied to each app's verdict (doc 2.5, 4.4)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..models import PolicyRule


def _app_matches(rule_app: str | None, app_id: str, name: str) -> bool:
    if not rule_app:
        return False
    r = rule_app.lower()
    base = app_id.replace("/", "\\").rsplit("\\", 1)[-1]
    return r in (app_id, base, name.lower())


def dest_matches(rule_dest: str | None, dest: str | None, raddr: str | None, domain: str | None) -> bool:
    if not rule_dest:
        return False
    r = rule_dest.lower().strip(".")
    for cand in (dest, domain):
        if cand and (cand == r or cand.endswith("." + r)):
            return True
    if raddr:
        try:
            if ipaddress.ip_address(raddr) in ipaddress.ip_network(r, strict=False):
                return True
        except ValueError:
            pass
    return dest == r


@dataclass(slots=True)
class AppPolicy:
    app_action: str | None = None  # allow | deny | mute (most severe app-wide rule)
    dest_rules: list[PolicyRule] = field(default_factory=list)

    def dest_action(self, dest: str | None, raddr: str | None = None, domain: str | None = None) -> str | None:
        acts = {r.action for r in self.dest_rules if dest_matches(r.dest, dest, raddr, domain)}
        for a in ("deny", "allow", "mute"):
            if a in acts:
                return a
        return None

    def dest_allowed(self, dest: str | None, raddr: str | None = None, domain: str | None = None) -> bool:
        return self.app_action == "allow" or self.dest_action(dest, raddr, domain) == "allow"


class PolicyEngine:
    def __init__(self) -> None:
        self.rules: list[PolicyRule] = []

    def load(self, rules: list[PolicyRule]) -> None:
        self.rules = rules

    def for_app(self, app_id: str, name: str, now: float) -> AppPolicy:
        pol = AppPolicy()
        app_actions = set()
        for r in self.rules:
            if r.expires_at is not None and r.expires_at <= now:
                continue
            if r.scope == "app" and _app_matches(r.app_id, app_id, name):
                app_actions.add(r.action)
            elif r.scope == "dest" or (r.scope == "app+dest" and _app_matches(r.app_id, app_id, name)):
                pol.dest_rules.append(r)
        for a in ("deny", "allow", "mute"):
            if a in app_actions:
                pol.app_action = a
                break
        return pol
