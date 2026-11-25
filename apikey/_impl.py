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


def _is_revoked(key: Mapping[str, Any]) -> bool:
    return bool(key.get("revoked"))


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

    # Quota belongs to this key alone. Other keys (even on the same account)
    # neither allocate nor consume it.
    quota = max(0, requested_quota)

    key = {
        "id": f"key-{sequence:06d}",
        "tenant": tenant,
        "account": account,
        # Owned copy: mutating the caller's scope list later cannot widen the
        # scopes bound to the issued key.
        "scopes": _scope_list(scopes),
        "quota": quota,
        "issued_at": now,
        "expires_at": now + ttl,
        "revoked": False,
        "revoked_at": None,
    }
    keys[key["id"]] = key
    return key


def check_scope(key: Mapping[str, Any], required: Sequence[str] | str) -> bool:
    """Return whether the key covers every required scope.

    Scopes are opaque, exact tokens: possessing ``read`` never implies
    ``readwrite`` or ``delete``. A key bound to no scopes cannot authorize
    anything, and a revoked key is always rejected.
    """
    if _is_revoked(key):
        return False
    scopes = _scope_list(key.get("scopes"))
    if not scopes:
        return False
    required_scopes = _scope_list(required)
    return all(
        any(item == granted for granted in scopes)
        for item in required_scopes
    )


def check_quota(key: Mapping[str, Any], usage: int, cost: int) -> bool:
    """Return whether the key can absorb cost on top of current usage.

    Spending exactly up to the quota is allowed; only exceeding it denies.
    A revoked key is always rejected.
    """
    if _is_revoked(key):
        return False
    return _as_int(usage) + _as_int(cost) <= _as_int(key.get("quota", 0))


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
    """Return whether the key may be used by the supplied tenant.

    The supplied tenant must be non-empty and exactly match the tenant the key
    was issued to, so a key can never cross tenant boundaries. A revoked key
    is always rejected.
    """
    if _is_revoked(key):
        return False
    bound_tenant = key.get("tenant")
    return bound_tenant is not None and bool(tenant) and bound_tenant == tenant


def check_expiry(key: Mapping[str, Any], now: int) -> bool:
    """Return whether the key is still inside its validity window.

    The window is right-open: the key is valid while ``now < expires_at`` and
    becomes invalid immediately upon reaching ``expires_at``. A revoked key is
    always rejected.
    """
    if _is_revoked(key):
        return False
    expires_at = key.get("expires_at")
    return expires_at is not None and now < expires_at


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
    # Approved in-batch cost per key. Different keys - including several keys
    # on the same account - never share a quota balance.
    spent_by_key: dict[Any, int] = {}

    for request in requests:
        key = request["key"]
        key_id = key.get("id")
        # Keys without an id are bucketed by object identity so distinct raw
        # dicts still stay independent.
        bucket: Any = key_id if key_id is not None else ("__object__", id(key))
        spent = spent_by_key.get(bucket, 0)

        required = request.get("required", policy.get("required_scopes", []))
        tenant = request.get("tenant", policy.get("tenant", key.get("tenant")))
        cost = _as_int(request.get("cost", policy.get("default_cost", 0)))
        # A request may state the key's current usage on top of which in-batch
        # spend is accumulated.
        baseline = _as_int(request.get("usage", 0))
        used = baseline + spent

        problems: list[str] = []
        if not check_scope(key, required):
            problems.append("scope")
        if not check_tenant(key, tenant):
            problems.append("tenant")
        if not check_expiry(key, now):
            problems.append("expiry")
        if not check_quota(key, used, cost):
            problems.append("quota")

        allowed = not problems
        if allowed:
            spent_by_key[bucket] = spent + cost

        results.append(
            {
                "key_id": key_id,
                "allowed": allowed,
                "problems": problems,
            }
        )

    return {"results": results}