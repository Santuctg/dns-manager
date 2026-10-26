"""WCAG contrast checks for the Console token palette in both themes."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOKENS = (ROOT / "app" / "static" / "css" / "tokens.css").read_text(encoding="utf-8")


def theme_vars(selector: str) -> dict[str, str]:
    body = TOKENS.split(selector, 1)[1].split("}", 1)[0]
    return dict(re.findall(r"--([a-z0-9-]+):\s*([^;]+);", body))


THEMES = {
    "dark": theme_vars(":root {"),
    "light": theme_vars('html[data-theme="light"]'),
}


def luminance(value: str) -> float:
    hex_value = value.strip().lstrip("#")
    channels = [int(hex_value[index:index + 2], 16) / 255 for index in (0, 2, 4)]

    def linear(channel: float) -> float:
        return channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(channel) for channel in channels)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast(foreground: str, background: str) -> float:
    first = luminance(foreground)
    second = luminance(background)
    return (max(first, second) + 0.05) / (min(first, second) + 0.05)


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_body_and_muted_text_meet_wcag_aa(theme):
    colors = THEMES[theme]
    for background in ("surface-0", "surface-1", "surface-2"):
        assert contrast(colors["text"], colors[background]) >= 4.5
        assert contrast(colors["text-muted"], colors[background]) >= 4.5


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_semantic_chip_colours_meet_wcag_aa(theme):
    colors = THEMES[theme]
    for name in ("good", "warning", "critical", "info"):
        assert contrast(colors[name], colors[f"{name}-tint"]) >= 4.5, name
        assert contrast(colors[name], colors["surface-2"]) >= 4.5, name
    assert contrast(colors["accent"], colors["accent-soft"]) >= 4.5
    assert contrast(colors["text-on-accent"], colors["accent"]) >= 4.5


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_faint_text_and_icons_still_reach_large_text_contrast(theme):
    colors = THEMES[theme]
    for background in ("surface-1", "surface-2"):
        assert contrast(colors["text-faint"], colors[background]) >= 3.0
    for name in ("good", "warning", "critical", "info", "accent"):
        assert contrast(colors[name], colors["surface-2"]) >= 3.0


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_borders_are_visible_against_surfaces(theme):
    colors = THEMES[theme]
    assert contrast(colors["border"], colors["surface-2"]) >= 1.2
    assert contrast(colors["border-strong"], colors["surface-2"]) >= 1.5


def test_light_theme_defines_every_colour_token():
    colour_tokens = {
        "surface-0", "surface-1", "surface-2", "surface-3", "surface-hover",
        "border", "border-strong", "text", "text-muted", "text-faint",
        "text-on-accent", "accent", "accent-strong", "accent-soft",
        "good", "warning", "critical", "info",
        "good-tint", "warning-tint", "critical-tint", "info-tint", "neutral-tint",
    }
    assert colour_tokens <= set(THEMES["dark"])
    assert colour_tokens <= set(THEMES["light"])
