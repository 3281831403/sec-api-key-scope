from apikey import check_scope, check_quota, issue, key_batch, revoke

NOW = 1_000


def _store():
    return {"keys": {}}


def _key(store, tenant="tenant-a", account="acct-1", scopes=None, quota=10, ttl=60):
    return issue(
        store,
        tenant,
        account,
        ["read"] if scopes is None else scopes,
        NOW,
        {"quota": quota, "ttl": ttl},
    )


def test_public_issue_binds_scopes_and_quota():
    store = _store()
    scopes = ["read"]
    key = issue(
        store,
        "tenant-a",
        "acct-1",
        scopes,
        NOW,
        {"quota": 10, "ttl": 60},
    )

    assert key["tenant"] == "tenant-a"
    assert key["account"] == "acct-1"
    assert key["quota"] == 10
    assert key["scopes"] == ["read"]

    scopes.append("delete")
    assert key["scopes"] == ["read"]


def test_public_read_scope_does_not_cover_readwrite():
    key = _key(_store(), scopes=["read"])

    assert check_scope(key, ["read"]) is True
    assert check_scope(key, ["readwrite"]) is False


def test_public_quota_exact_remaining_is_allowed():
    key = _key(_store(), scopes=["read"], quota=10)

    assert check_quota(key, 7, 3) is True
    assert check_quota(key, 7, 4) is False


def test_public_revoke_takes_effect():
    store = _store()
    key = _key(store, scopes=["read"], quota=10)

    revoke(store, key["id"], NOW + 1)

    assert check_scope(key, ["read"]) is False


def test_public_batch_two_keys_independent():
    store = _store()
    first = _key(store, tenant="tenant-a", account="acct-1", scopes=["read"], quota=50, ttl=100)
    second = _key(store, tenant="tenant-b", account="acct-2", scopes=["read"], quota=50, ttl=100)

    result = key_batch(
        [
            {"key": first, "tenant": "tenant-a", "required": ["read"], "cost": 40},
            {"key": second, "tenant": "tenant-b", "required": ["read"], "cost": 20},
        ],
        {},
        NOW + 1,
    )

    assert [item["allowed"] for item in result["results"]] == [True, True]