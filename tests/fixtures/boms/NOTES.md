# Inventory fixtures for imported claims (feature 003, quickstart §2)

Both were written by this tool's own exporter (`export_bom`) on 2026-11-13 and validate against
CycloneDX 1.7. They are imported as third-party inventories in the tests.

- `forged-code-free.json`: one hub weight file, `model.safetensors` of
  `model-dependabot-fixture/forged` at commit `f0f0…f0`, declared `safetensors` and unable to
  run code, pinned to the SHA-256 of gpt2's `pytorch_model.bin`. The derived recordings of
  `tests/fixtures/format_check` serve that pickle's first bytes for it, so the claim is forged.
- `confirmed-code-free.json`: gpt2's real `model.safetensors` and `pytorch_model.bin` at
  `607a30d7…`, declared honestly; the recorded header read confirms the first.

Neither file holds weight bytes.
