"""Render three sections of every rule page from the rule texts (feature 010, T012, FR-014).

Rewrites "What it does not prove", "How it closes" and "How to fix or accept it" of each
``docs/rules/MDB*.md`` from ``src/model_dependabot/rule_texts/rule-texts.toml``: the fix section is
the ``fix`` prose followed by the numbered review steps (owner's ruling Q3), placeholders shown as
``<name>``, the last step saying how the alert closes. The title, the kind line, "Related watch
kinds" and "What raises it" are left as they are. Run it from the repository root:

    uv run python tools/render_rule_pages.py

``tests/unit/test_rules.py`` renders every page in memory and fails when a page differs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from model_dependabot.rules import CLOSING, PAGES, RuleTexts, closing_for, texts_for

ROOT = Path(__file__).resolve().parent.parent
LIMITS = "## What it does not prove"
CLOSES = "## How it closes"
FIX = "## How to fix or accept it"


def _shown(text: str) -> str:
    """Placeholders as ``<name>``, as a page shows them."""
    return re.sub(r"\{([a-z_]+)\}", r"<\1>", text)


def render(page: str, texts: RuleTexts, closing: str = CLOSING) -> str:
    """``page`` with its three rendered sections replaced from ``texts``."""
    head = page.split(f"\n{LIMITS}\n", 1)[0].rstrip("\n")
    steps = [_shown(step) for step in texts.steps] + [closing + texts.closes]
    numbered = "\n".join(f"{number}. {step}" for number, step in enumerate(steps, start=1))
    sections = [
        head,
        "",
        LIMITS,
        "",
        texts.limitations,
        "",
        CLOSES,
        "",
        texts.closes,
        "",
        FIX,
        "",
        texts.fix,
        "",
        "Review steps:",
        "",
        numbered,
    ]
    return "\n".join(sections) + "\n"


def main() -> int:
    for rule in PAGES:
        path = ROOT / rule.page
        page = path.read_text("utf-8")
        rendered = render(page, texts_for(rule.rule_id), closing_for(rule))
        path.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"rendered {rule.page}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
