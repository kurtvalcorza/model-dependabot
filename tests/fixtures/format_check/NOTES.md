# format-check fixtures (feature 003, research A4)

Recorded on 2026-11-12 (16:20 UTC) with `uv run python tools/record_fixtures.py format-check`:
anonymous, no token, User-Agent `model-dependabot/0.1.0`. Each ranged request sends
`Range: bytes=0-1048575` and is recorded hop by hop, so `RecordedFetcher` replays the redirect
too; every hop's meta file carries that `range` key.

| Recording | Request | Notes |
| :-- | :-- | :-- |
| `openai-community--gpt2-tree` | tree of `openai-community/gpt2` at `607a30d7…` | Byte-exact |
| `gpt2-safetensors-range`, `-range-1` | `model.safetensors`: 302 to the storage host, then 206 | 1 MiB lead of a real safetensors file (header 14,283 bytes); `Content-Range: bytes 0-1048575/548105171` |
| `gpt2-pickle-range`, `-range-1` | `pytorch_model.bin`: 302, then 206 | 1 MiB lead of a protocol 2 pickle |
| `TheBloke--TinyLlama-1.1B-Chat-v1.0-GGUF-tree` | tree at `52e7645b…` | Byte-exact |
| `tinyllama-gguf-range`, `-range-1` | `tinyllama-1.1b-chat-v1.0.Q2_K.gguf`: 302, then 206 | 1 MiB lead of a GGUF file |
| `hf-internal-testing--tiny-random-bert-tree` | tree at `f171d7ba…` | Byte-exact |
| `tiny-bert-zip-range`, `-range-1` | `pytorch_model.bin`: 302, then 206 | A zip (PyTorch archive) of 540,217 bytes: the whole file fits in the lead, so its central directory is read |
| `hf-internal-testing--dummy-gated-model-tree` | tree at `9a039e12…` | Byte-exact; `gated_file.txt` is outside LFS, so the hub gives no SHA-256 for it |
| `gated-refused-range` | `gated_file.txt` | The hub's real anonymous refusal: HTTP 401 (`X-Error-Code: GatedRepo`) |

Trimmed: the storage host's redirect target is a signed URL; its query string (signature,
expiry, key id) is removed from `redirected_to`, from the 302 body that repeats it and from the
storage hop's recorded `url`, and the 302's `content-length` header is dropped. Nothing else is
changed. Only `content-type`, `content-range`, `content-length`, `x-repo-commit` and
`x-error-code` headers are kept.

Derived in the tests by `derive_format_check` (`tests/conftest.py`), never committed: a tree that
lists the gated file with a hash (so its real 401 is reached), 403 and 404 refusals, a 503, a
network error, a 206 cut off mid-read, a server that ignores the range and answers 200, a
safetensors header longer than the lead or than the 16 MiB limit, and the forged repository
`model-dependabot-fixture/forged`, whose `model.safetensors` is listed with gpt2's pickle hash
and serves that pickle's recorded lead (a pickle named as a code-free format).

The live test `tests/live/test_live_format_check.py` checks that the hub still answers this way.
