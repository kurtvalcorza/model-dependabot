# Rule texts

`rule-texts.toml` is the one source of the fixed text of each rule ID (feature 010, FR-014). The
advisory view (`alert show ALERT_ID --advice`, `alerts ID --advice`) and the rule pages under
`docs/rules/` both read it, so a maintainer sees the same words in both places.

## What it holds

One table per rule ID of `src/model_dependabot/rules.py`, and no other table:

- `limitations`: what the check cannot see; the page's "What it does not prove" section.
- `closes`: how the alert closes; the page's "How it closes" section, and the last review step,
  introduced as `How this alert closes:`.
- `fix`: the page's "How to fix or accept it" prose.
- `not_established`: what the evidence does not answer, two or more items; the first is always
  `whether this alert affects model {model_id}`.
- `steps`: the numbered review steps, two or more, before the closing step. Each names only commands
  the CLI has today and is something the maintainer does; none says the tool acts.

`rules.py` loads the file once and refuses it when a rule ID is missing or extra, a field is missing
or empty, `steps` has fewer than two items, the impact question is not first or a placeholder is not
on the list below.

## Placeholders

`steps` and `not_established` may use only `{alert_id}`, `{model_id}`, `{identifier}`,
`{location}`, `{package}`, `{version}`, `{advisory_ids}`, `{dataset}`, `{paper_doi}`, `{repo}`,
`{item}` and `{rule_doc}`. The view fills them from the alert's stored fields only; a value the alert
does not hold is shown as `not recorded`. The rule pages show them as `<name>`.

## The rule pages

The "What it does not prove", "How it closes" and "How to fix or accept it" sections of every
`docs/rules/MDB*.md` page are rendered from this file by `tools/render_rule_pages.py`; the fix
section is the `fix` prose followed by the numbered steps. Edit this file, then run

    uv run python tools/render_rule_pages.py

and commit both. A test renders every page in memory and fails when a page differs.

## Version

`version` is an integer. Bump it with any change to the text, and record the new file's SHA-256 in
`tests/unit/test_rule_texts.py`; the test fails when the text changes without a new version.
