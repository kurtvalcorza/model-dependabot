# Validation record: feature 001

Recorded on 2026-10-24 on branch `001-inventory-alerts` (base commit `68051ec`), Windows 11, Python
3.12.10, uv 0.13.5. Exit codes are the commands' own (no pipes in front of them). Timings are wall-clock
and vary between runs on this host by a factor of about three.

## T054: full suite with the network blocked, and ruff

`tests/conftest.py` blocks `socket.connect`, `connect_ex`, `create_connection` and `getaddrinfo` in
every test not marked `live`. As a second guard the run also points every proxy at a closed port.

| Command | Result | Exit |
| :-- | :-- | :-- |
| `HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 uv run pytest -q` | 384 passed, 3 deselected (the `live` tests), 6.95 s | 0 |
| `uv run ruff check` | All checks passed | 0 |
| `uv run ruff format --check` | 84 files already formatted | 0 |
| `uv run pytest -m live -q` | 3 passed, 384 deselected, 1.28 s | 0 |

Baseline before this phase: 371 passed, exit 0, 31.3 s. Added: 7 tests in `tests/unit/test_reports.py`,
4 in `tests/contract/test_cli_json.py`, 2 in `tests/integration/test_never_writes.py` and 3 `live`
tests in `tests/live/test_live_sources.py`.

### Live smoke tests (T052)

Run once, anonymously, with the generic User-Agent `model-dependabot/0.1.0`; 2 network requests in all.

| Test | Request | Outcome |
| :-- | :-- | :-- |
| `test_osv_querybatch_answers_in_the_recorded_format` | `POST https://api.osv.dev/v1/querybatch` for pillow 12.3.0 | passed: the answer parses and still lists both recorded advisories (`GHSA-24rc-8hj2-v98c`, `GHSA-cp9v-662q-vvx9`) |
| `test_hub_tree_at_a_pinned_commit_matches_the_recording` | `GET https://huggingface.co/api/models/openai-community/gpt2/tree/607a30d7…` | passed: same file list, and `model.safetensors` has the recorded SHA-256 and size |
| `test_user_agent_is_generic` | none | passed |

No source answered differently from its recorded fixture.

### Test speed

The suite's time was dominated by SQLite syncing to disk on every commit. An autouse fixture in
`tests/conftest.py` now opens every connection made during a test with `PRAGMA synchronous = OFF`;
production code is unchanged and keeps SQLite's default (`FULL`).

| Fixture | Run 1 | Run 2 |
| :-- | :-- | :-- |
| off (production default) | 36.9 s | 35.8 s |
| on | 7.6 s | 17.9 s |

## Performance checks (plan.md Performance Goals)

Run by a script outside the repository against a temporary folder that was deleted afterwards
(`tempfile.TemporaryDirectory`); nothing from it was committed. Both use recorded or derived
responses, so they measure the tool's own work and not network latency.

| Check | Target | Result | Exit |
| :-- | :-- | :-- | :-- |
| `register` of the worked example (`tests/fixtures/manifests/example.toml`) plus a synthetic 629,145,600-byte (0.6 GB) local weight file, 629,145,916 bytes of weights in all; hub answers from `tests/fixtures/hf` | under 5 minutes (SC-001) | 0.45 s; 11 entries, 2 gaps | 0 |
| `check` (all three sources) of a model with 100 hash-locked packages (pillow 12.3.0, validators 0.12.2 and 98 synthetic packages); OSV answer derived from the recorded `querybatch-vulnerable` answer, with empty results for the synthetic packages | under 60 seconds | 0.04 s; 2 alerts opened; `osv`, `picklescan` and `hf-scan` all `ok` | 0 |

The hashing figure is consistent with this host's raw SHA-256 rate (about 4.1 GB/s measured with
`hashlib`), but the file had just been written, so it was read from the page cache; a cold read from
disk will be slower. The walk-through on a real inventory (T055) records the times with the network.

## T054a: the service never writes (FR-017)

`tests/integration/test_never_writes.py` runs `register`, `check`, `policy`, `alerts`, `alert dismiss`
and `inventory export` on a copy of the worked example with a spying fetcher. Requests seen: `GET` and
one kind of `POST`, to `https://api.osv.dev/v1/querybatch`; no `PUT`, `PATCH` or `DELETE`; every hub
request is under `https://huggingface.co/api/models/`. The SHA-256 and modification time of the
manifest, the lock and all three local weight files are unchanged after `register`, after `check` and
at the end. A second test checks that `UrlFetcher` has no `put`, `patch`, `delete` or `request` method.
The property already held, so the test passed on its first run.

## T056: neutrality and privacy

`P` is a case-insensitive search for the owner's institution, programme and personal names, their
domains and generic academic and government words; the list itself is kept outside the repository.

| Command | Result |
| :-- | :-- |
| `grep -rniE "$P" src tests tools README.md research specs` | 6 lines. 5 are licence names in the vendored SPDX schema (`src/model_dependabot/inventory/schema/spdx.schema.json`: University of California, Nara Institute of Science and Technology, University of Illinois), third-party data. 1 is `specs/001-inventory-alerts/plan.md:58`, which names the first platform's programme in the constitution check (G0-02, open for the owner) |
| `grep -rnoE "<email pattern>" src tests tools README.md research specs` | 3: two schema authors' addresses in the vendored CycloneDX and JSF schemas, and `someone@example.org` (a reserved example domain) in `tests/unit/test_fetcher.py`, used to prove an email in the User-Agent is refused |
| `grep -rnE "hf_…\|ghp_…\|github_pat_\|sk-…\|Bearer \|Authorization\|AKIA…"` over the same paths | none |
| `git log --format=%B \| grep -ciE "$P"` | 0 commit messages match |
| `git log --format=%B` email addresses | only `noreply@anthropic.com` (co-author lines), 16 commits |
| `git log --format='%an <%ae>'` | one author with a GitHub `users.noreply.github.com` address, 16 commits |
| User-Agent | `DEFAULT_USER_AGENT = f"model-dependabot/{__version__}"` (`src/model_dependabot/sources/fetcher.py:26`); `UrlFetcher` refuses a User-Agent with an email address (line 187); no token is sent anywhere (`tools/record_fixtures.py` docstring and the fetcher) |
| `rice` (excluding `price`) in `src`, `tests`, `tools`, `research` | none; the worked-example id `rice-pest-r50-v5` appears only in `specs/001-inventory-alerts/contracts/cli.md`, `contracts/manifest.md` and `quickstart.md` |

Third-party repository ids used only as test data (`openai-community/gpt2`, `mcpotato/42-eicar-street`)
are not institution names. Open for the owner: the programme name in `plan.md:58` and the
domain-specific worked-example id in the contracts and quickstart; neither is in code, tests or the
README.

## T055: walk-through on a real inventory

Run 2026-10-24 by the orchestrator, owner's choice of model: the rice pest detector, RT-DETR r50 v5.
The manifest and databases lived in a temporary folder outside the repository; the model's own
repositories were only read.

Inventory: two weight files (`best.pt`, 171,769,415 bytes, `sha256:e0ae635d…`; the ONNX export,
171,744,970 bytes), the hash-locked Kaggle lock (`requirements-kaggle.lock.txt`, 61 packages, 926
hashes, uv-generated), base model `PekingU/rtdetr_r50vd` at `df939e661d8c52e80608d1ec566561aabd25a4e7`,
dataset DOI `10.5281/zenodo.20066074`.

| Section | Command | Result | Exit |
| :-- | :-- | :-- | :-- |
| 1 | `uv run pytest -q` | 384 passed, 3 deselected (above) | 0 |
| 2 | `register`, `inventory show`, `inventory export`, `import` | 65 entries (2 weight files, 61 packages, 1 base model, 1 dataset), 0 gaps; export then import gives identical entries | 0 |
| 3 | `check` (osv, picklescan, hf-scan), `alerts --json` | 1.9 s, all sources ok; 0 alerts | 0 |
| 3, cross-check | OSV `querybatch` for the 61 packages, sent directly | 0 packages with advisories (lock pins Pillow 13.0.0) | n/a |
| 4 | same check | 1 `pickle_format` watch event for `best.pt` (PyTorch zip); nothing for the ONNX file | 0 |
| 4, cross-check | `picklescan.scan_file_path` on `best.pt` directly | 4 globals, all innocuous, 0 infected | n/a |
| 5 | v1 with the lock as it was before commit `b46d1da` (Pillow 12.3.0), `check`; then v2 with today's lock | v1: 41 `package_advisory` alerts for Pillow 12.3.0 (top severity CRITICAL); v2 `register`: all 41 closed as `fixed`, `closed_by_version` 2, 0 open; no source consulted | 0 |
| 6 | `check --source osv` with `HTTPS_PROXY` pointed at a closed port | source failed; 41 open alerts unchanged | 2 |
| 7 | scheduling | not run; `check --all` from the host scheduler, documented in README | n/a |

Timings: registration 1.1 s (v1) and 5.0 s (v2) with warm caches, so far inside SC-001's 5 minutes;
`check` 1.9 s for 61 packages and 18.3 s when opening 41 alerts (detail fetch per advisory, within
OSV's limits), inside the 60-second goal. The SHA-256 of `best.pt` was the same before and after
(FR-017). The model repository's uncommitted files predate this run (dated 2026-10-19).
