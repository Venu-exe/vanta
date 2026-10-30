"""Registry / plugin-discovery tests."""

from vanta.core import registry


def test_discovery_finds_builtin_modules():
    registry.discover()
    mods = registry.all_modules()
    for expected in ("subdomains", "portscan", "techdetect", "http-headers", "tls-audit", "sqli"):
        assert expected in mods, f"{expected} was not discovered"


def test_modules_have_metadata():
    registry.discover()
    for name, cls in registry.all_modules().items():
        assert cls.name == name
        assert cls.category
        assert cls.description


def test_active_modules_are_flagged():
    registry.discover()
    assert registry.get("portscan").active is True
    assert registry.get("techdetect").active is False


def test_select_sorts_into_kill_chain_order():
    registry.discover()
    chosen = registry.select(names=["sqli", "subdomains", "portscan"])
    names = [c.name for c in chosen]
    assert names == ["subdomains", "portscan", "sqli"]  # phase order


def test_select_by_category():
    registry.discover()
    chosen = registry.select(categories=["recon"])
    assert chosen
    assert all(c.category == "recon" for c in chosen)
