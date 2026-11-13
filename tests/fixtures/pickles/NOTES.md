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
| `posix-path.pkl` | yes | Builds `pathlib.PosixPath` from a string; suspicious to the scanner (feature 004, FR-007) |
| mixed pickle | **no** | `collections.OrderedDict` (innocuous), `model_dependabot_fixture.layers.CustomLayer` (suspicious) and `os.system` (dangerous) (`craft.mixed()`) |
| protocol 2 getattr pickle | **no** | `__builtin__.getattr` (dangerous), `__builtin__.set`, `torch.Size` and the custom layer class (suspicious), as older checkpoints write them (`craft.protocol2_getattr()`) |
| two dangerous globals | **no** | `os.system` and `builtins.eval` (`craft.two_dangerous()`) |
| unresolved import | **no** | A protocol 4 `STACK_GLOBAL` whose module operand is an integer, not a string constant; picklescan 1.0.5 reports it as `unknown.eval`, dangerous (`craft.unresolved()`) |

The fixtures that import a dangerous global are built at test time into the test's temporary directory
(`craft.dangerous()`, `craft.pytorch_zip(...)` and the four feature 004 builders above), never committed, because antivirus or repository
scanning may quarantine or flag a committed file that imports `os.system`. This departs from the
wording of task T035, which places all four fixtures in this directory. A test checks that the
committed files are byte-identical to what `craft.py` builds, and another that each feature 004
fixture scans as this table says (`tests/unit/test_pickle_scan.py`).

Rebuild the committed files with `uv run python tests/fixtures/pickles/craft.py`.
