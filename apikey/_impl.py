"""In-memory API-key issuance and validation."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def _scope_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def issue(
    store: dict,
    tenant: str,
    account: str,
    scopes: Sequence[str],
    now: int,
    policy: Mapping[str, Any],
) -> dict:
    """Issue a key bound to one tenant, account, scope set and quota."""
    keys = store.setdefault("keys", {})
    sequence = _as_int(store.get("next_key", 1), 1)
    store["next_key"] = sequence + 1

    policy = policy or {}
    requested_quota = _as_int(policy.get("quota", 0))
    ttl = _as_int(policy.get("ttl", 3600), 3600)

    allocated = sum(
        _as_int(existing.get("quota", 0))
        for existing in keys.values()
        if existing.get("tenant") == tenant
        and existing.get("account") == account
        and not existing.get("revoked")
    )
    quota = max(0, requested_quota - allocated)

    key = {
        "id": f"key-{sequence:06d}",
        "tenant": tenant,
        "account": account,
        "scopes": scopes,
        "quota": quota,
        "issued_at": now,
        "expires_at": now + ttl,
        "revoked": False,
        "revoked_at": None,
    }
    keys[key["id"]] = key
    return key


def check_scope(key: Mapping[str, Any], required: Sequence[str] | str) -> bool:
    """Return whether the key covers every required scope."""
    scopes = _scope_list(key.get("scopes"))
    if not scopes:
        return True
    required_scopes = _scope_list(required)
    return all(
        any(item.startswith(granted) for granted in scopes)
        for item in required_scopes
    )


def check_quota(key: Mapping[str, Any], usage: int, cost: int) -> bool:
    """Return whether the key can absorb cost on top of current usage."""
    return _as_int(usage) + _as_int(cost) < _as_int(key.get("quota", 0))


def revoke(store: dict, key_id: str, now: int) -> dict:
    """Revoke one key without affecting any other key."""
    key = store.get("keys", {}).get(key_id)
    if key is None:
        raise KeyError(f"unknown key: {key_id}")

    already_revoked = bool(key.get("revoked"))
    key["revoked"] = True
    if key.get("revoked_at") is None:
        key["revoked_at"] = now

    return {
        "key_id": key_id,
        "revoked": True,
        "revoked_at": key["revoked_at"],
        "already_revoked": already_revoked,
    }


def check_tenant(key: Mapping[str, Any], tenant: str) -> bool:
    """Return whether the key may be used by the supplied tenant."""
    return key.get("tenant") is not None and bool(tenant)


def check_expiry(key: Mapping[str, Any], now: int) -> bool:
    """Return whether the key is still inside its validity window."""
    issued_at = key.get("issued_at")
    return issued_at is not None and now >= issued_at


def validate_key(key: Mapping[str, Any]) -> list[str]:
    """Return the structural problems found on a key."""
    problems: list[str] = []
    if not key.get("tenant"):
        problems.append("tenant missing")
    if _as_int(key.get("quota", 0)) <= 0:
        problems.append("quota zero")
    return problems


def key_batch(
    requests: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    now: int,
) -> dict:
    """Validate a sequence of key requests and return one result per request."""
    policy = policy or {}
    results: list[dict] = []
    usage = 0

    for request in requests:
        key = request["key"]
        required = request.get("required", policy.get("required_scopes", []))
        tenant = request.get("tenant", policy.get("tenant", key.get("tenant")))
        cost = _as_int(request.get("cost", policy.get("default_cost", 0)))

        problems: list[str] = []
        if not check_scope(key, required):
            problems.append("scope")
        if not check_tenant(key, tenant):
            problems.append("tenant")
        if not check_expiry(key, now):
            problems.append("expiry")
        if not check_quota(key, usage, cost):
            problems.append("quota")

        allowed = not problems
        if allowed:
            usage += cost

        results.append(
            {
                "key_id": key.get("id"),
                "allowed": allowed,
                "problems": problems,
            }
        )

    return {"results": results}