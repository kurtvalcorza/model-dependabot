# Pickle fixtures

Built by `craft.py` as raw pickle opcode bytes; nothing here is ever pickled or unpickled, and the
tests only disassemble them with the scanner.

| File | Committed | Content |
| :-- | :-- | :-- |
| `innocuous.pkl` | yes | Imports `collections.OrderedDict` and `torch._utils._rebuild_tensor_v2` only |
| `suspicious.pkl` | yes | Imports `model_dependabot_fixture.layers.CustomLayer`, on neither scanner list |
| `joblib-style.joblib` | yes | Pickle opcodes, then 16 bytes of raw float32 array data, then the end of the stream (FR-022) |
| dangerous pickle | **no** | Imports `os.system` (with the harmless argument `echo model-dependabot fixture`) |
| dangerous PyTorch zip | **no** | The dangerous pickle as `archive/data.pkl` in a PyTorch zip archive |

The two dangerous fixtures are built at test time into the test's temporary directory
(`craft.dangerous()`, `craft.pytorch_zip(...)`), never committed, because antivirus or repository
scanning may quarantine or flag a committed file that imports `os.system`. This departs from the
wording of task T035, which places all four fixtures in this directory. A test checks that the
committed files are byte-identical to what `craft.py` builds.

Rebuild the committed files with `uv run python tests/fixtures/pickles/craft.py`.
