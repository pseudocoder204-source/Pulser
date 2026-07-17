#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Office-tier scope gate for the multi-host audit coordinator.

mark2's existing scope gate (agent.py: resolve_scope / make_scope_token /
verify_scope_token) binds an HMAC token to exactly one target string — there is no
notion of a range. Per Enterprise/Notes/office-audit-plan.txt Layer 0, the office
audit needs to authorize a whole CIDR once, then mint a token per discovered host
that is only valid if that host is actually contained in the enrolled CIDR.

This module adds that containment check as a layer ON TOP of the existing gate,
without modifying agent.py at all:

    resolve_office_scope(cidr)                    -- enroll a CIDR, once
        -> office_token
    mint_host_token(cidr, office_token, host_ip)   -- per discovered host
        -> host_token  (an agent.py-native scope_token, verified by the
                         unmodified _WORKERS spine exactly as it is today)

The host-level token returned by mint_host_token() is produced by calling
agent.resolve_scope(host_ip) directly -- so it is byte-for-byte the same kind of
token the existing single-target spine already knows how to verify. No new trust
primitive is introduced; this module only adds the "is this host actually inside
the range the operator enrolled" gate in front of it.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import time

import agent

__all__ = [
    "OfficeScopeError",
    "resolve_office_scope",
    "verify_office_scope",
    "mint_host_token",
]

_OFFICE_SCOPE_SECRET = os.environ.get("ENTERPRISE_SCOPE_SECRET") or secrets.token_hex(16)
_OFFICE_SCOPE_TTL_SECONDS = 3600


class OfficeScopeError(Exception):
    """Raised when a CIDR enrollment or a per-host containment check fails."""


def _normalize_cidr(cidr: str) -> str:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError) as exc:
        raise OfficeScopeError(f"Invalid CIDR format: {cidr!r}") from exc
    return str(network)


def _make_office_token(cidr: str, ttl: int = _OFFICE_SCOPE_TTL_SECONDS) -> str:
    expiry = int(time.time()) + ttl
    mac = hmac.new(
        _OFFICE_SCOPE_SECRET.encode(),
        f"{cidr}|{expiry}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{expiry}:{mac}"


def resolve_office_scope(cidr: str, ttl: int = _OFFICE_SCOPE_TTL_SECONDS) -> str:
    """Validate the CIDR and mint an office-level scope token for it.

    Raises OfficeScopeError if the CIDR is malformed.
    """
    normalized = _normalize_cidr(cidr)
    return _make_office_token(normalized, ttl=ttl)


def verify_office_scope(cidr: str, token: str) -> bool:
    """Check that `token` is a valid, unexpired office-scope token for `cidr`."""
    try:
        normalized = _normalize_cidr(cidr)
    except OfficeScopeError:
        return False
    try:
        expiry_str, mac = token.split(":", 1)
        expiry = int(expiry_str)
    except (ValueError, AttributeError):
        return False
    if time.time() > expiry:
        return False
    expected = hmac.new(
        _OFFICE_SCOPE_SECRET.encode(),
        f"{normalized}|{expiry}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(mac, expected)


def mint_host_token(cidr: str, office_token: str, host_ip: str) -> str:
    """Mint a per-host agent.py scope token, gated by CIDR containment.

    Only succeeds if `office_token` is a valid, unexpired token for `cidr`, AND
    `host_ip` actually falls inside `cidr`. The returned token is minted by
    agent.resolve_scope(host_ip) verbatim -- it is consumed by the existing,
    unmodified _WORKERS spine in agent.py exactly like a single-target run.

    Raises OfficeScopeError on any failure (invalid/expired office token,
    malformed CIDR, host outside the enrolled range, or an invalid host format
    rejected by agent.py's own target validation).
    """
    if not verify_office_scope(cidr, office_token):
        raise OfficeScopeError("office scope token invalid or expired for this CIDR")

    network = ipaddress.ip_network(_normalize_cidr(cidr), strict=False)
    try:
        address = ipaddress.ip_address(host_ip)
    except ValueError as exc:
        raise OfficeScopeError(f"Invalid host IP format: {host_ip!r}") from exc

    if address not in network:
        raise OfficeScopeError(f"Host {host_ip} is outside enrolled CIDR {network}")

    try:
        return agent.resolve_scope(host_ip)
    except agent.ScopeError as exc:
        raise OfficeScopeError(str(exc)) from exc
