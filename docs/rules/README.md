# Rule IDs

Every alert kind has one rule ID, `MDB` plus three digits, grouped by family. An ID is never reused,
even if its kind is retired. Each ID has its own page, with what raises the alert, what it does not
prove, how it closes and how to fix or accept it.

| Rule ID | Alert kind | Family |
| :-- | :-- | :-- |
| [`MDB101`](MDB101.md) | `weight_file_scan` | weight files |
| [`MDB102`](MDB102.md) | `hub_scan` | weight files |
| [`MDB103`](MDB103.md) | `format_policy` | weight files |
| [`MDB104`](MDB104.md) | `globals_policy` | weight files |
| [`MDB201`](MDB201.md) | `package_advisory` | packages |
| [`MDB301`](MDB301.md) | `dataset_retracted` | datasets and papers |
| [`MDB302`](MDB302.md) | `paper_retracted` | datasets and papers |
| [`MDB303`](MDB303.md) | `dataset_removed` | datasets and papers |
| [`MDB304`](MDB304.md) | `dataset_not_findable` | datasets and papers |
| [`MDB401`](MDB401.md) | `licence_changed` | licences |
| [`MDB501`](MDB501.md) | `base_model_disabled` | base model |
| [`MDB502`](MDB502.md) | `base_model_unavailable` | base model |

One watch kind has a page of its own because it can carry a finding of any travelling kind
(feature 011): it is a watch event, never an alert.

| Rule ID | Watch kind | Family |
| :-- | :-- | :-- |
| [`MDB601`](MDB601.md) | `lineage_inherited` | lineage |

The registry is `src/model_dependabot/rules.py`; every alert in every view carries its `rule_id` and
`rule_doc`, and text output shows the ID after the alert id.

Three sections of each page, "What it does not prove", "How it closes" and "How to fix or accept it"
(the fix prose and the numbered review steps), are rendered from
`src/model_dependabot/rule_texts/rule-texts.toml` by `tools/render_rule_pages.py`; edit that file,
not the page, and run the tool. The advisory view (`alert show ALERT_ID --advice`) shows the same
texts. "What raises it" is written by hand.
