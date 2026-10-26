"""Both dictionaries must be complete, key-identical and placeholder-safe."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
I18N = ROOT / "app" / "static" / "i18n"

PLACEHOLDER = re.compile(r"\{(\w+)\}")


def load(lang: str) -> dict[str, str]:
    return json.loads((I18N / f"{lang}.json").read_text(encoding="utf-8"))


def literal_keys(text: str) -> set[str]:
    return set(re.findall(r"\bt\(\s*['\"]([^'\"]+)['\"]", text))


def used_keys() -> set[str]:
    keys: set[str] = set()
    for path in (ROOT / "app" / "templates").glob("*.html"):
        keys |= literal_keys(path.read_text(encoding="utf-8"))
    for path in (ROOT / "app" / "static" / "js").rglob("*.js"):
        keys |= literal_keys(path.read_text(encoding="utf-8"))
    web = (ROOT / "app" / "web.py").read_text(encoding="utf-8")
    keys |= set(re.findall(r"translate\([^,]+,\s*['\"]([^'\"]+)['\"]", web))
    keys |= set(re.findall(r"PAGE_TITLES[^}]*?\"([a-z_]+\.[a-z_]+)\"", web, re.S))
    return keys


def test_en_and_bn_have_identical_keys():
    en, bn = load("en"), load("bn")
    assert set(en) == set(bn)
    assert len(en) > 350


def test_every_key_used_by_templates_and_modules_exists():
    en, bn = load("en"), load("bn")
    missing_en = sorted(used_keys() - set(en))
    missing_bn = sorted(used_keys() - set(bn))
    assert missing_en == []
    assert missing_bn == []


def test_placeholders_match_between_languages():
    en, bn = load("en"), load("bn")
    broken = {
        key: (sorted(PLACEHOLDER.findall(en[key])), sorted(PLACEHOLDER.findall(bn[key])))
        for key in en
        if set(PLACEHOLDER.findall(en[key])) != set(PLACEHOLDER.findall(bn[key]))
    }
    assert broken == {}


def test_no_empty_translations():
    for lang in ("en", "bn"):
        empty = [key for key, value in load(lang).items() if not str(value).strip()]
        assert empty == [], lang


def test_technical_terms_stay_english_in_bengali():
    bn = load("bn")
    for key in ("nav.ssl", "mappings.flag.https", "mappings.flag.ws", "mappings.flag.host"):
        value = bn[key]
        assert re.search(r"[A-Za-z]", value), (key, value)
    assert "UFW" in bn["firewall.subtitle"]
    assert "SSL" in bn["ssl.subtitle"] or "SSL" in bn["nav.ssl"]
