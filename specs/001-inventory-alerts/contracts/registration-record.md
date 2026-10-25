# Contract: registration record (schema version "1")

A registration record lets a model be registered on a machine that does not hold its weight files, for
example a hosted CI job, where the weights are ignored by git and stay on the owner's machine. It is
made with `record` on the machine that holds the files and read with `register --from-record`
([cli.md](cli.md)). It is plain JSON text, small enough to review in a pull request.

`record` reads the [manifest](manifest.md) and, for each local weight file (`[[weights]] path = ...`)
in manifest order:

- hashes it with SHA-256, read in chunks, never whole;
- classifies its format and whether loading it can run code (research R4, the same rule as `register`);
- for a file that can run code, scans it with the local pickle scanner (`picklescan`, research R4):
  hashed, scanned and hashed again through one handle; if the two hashes differ nothing is written.

Hub weight files (`[[weights]] hub = ...`) are not in the record: they are pinned from the hub when the
record is registered, as with `register`. Nothing else in the manifest is in the record either.

## Shape

```json
{
  "schema_version": "1",
  "model_id": "example-detector-v1",
  "manifest_sha256": "<SHA-256 of the manifest, CRLF read as LF>",
  "generator": {"name": "model-dependabot", "version": "0.1.0"},
  "weights": [
    {
      "location": "weights/best.pt",
      "sha256": "<64 lower-case hex digits>",
      "size": 1234,
      "format": "pytorch-zip",
      "can_run_code": true,
      "scan": {
        "scanner": "picklescan",
        "scanner_version": "1.0.5",
        "file_name": "best.pt",
        "size": 1234,
        "complete": true,
        "position": 1234,
        "error": null,
        "globals": [{"module": "collections", "name": "OrderedDict", "safety": "innocuous"}],
        "verdict": "clean",
        "scanned_at": "2026-10-25T08:00:00Z"
      }
    },
    {
      "location": "weights/model.safetensors",
      "sha256": "<64 lower-case hex digits>",
      "size": 5678,
      "format": "safetensors",
      "can_run_code": false,
      "scan": null
    }
  ],
  "record_sha256": "<SHA-256 of the canonical JSON of every other field>"
}
```

| Field | Rule |
| :-- | :-- |
| `schema_version` | `"1"`. A reader refuses any other value |
| `model_id` | The manifest's `model.id` |
| `manifest_sha256` | SHA-256 of the manifest's bytes with each CRLF read as LF, so a checkout with other line endings is the same manifest |
| `generator` | The tool and version that made the record; informational |
| `weights` | One item per local weight file, in manifest order; `location` is the manifest's `path` exactly as written |
| `sha256`, `size` | Of the file's bytes |
| `format`, `can_run_code` | As in the inventory entry ([data-model.md](../data-model.md)): `safetensors`, `onnx` and `gguf` cannot run code; `pickle`, `joblib` and `pytorch-zip` can; `unknown` is `null` |
| `scan` | Required for a file whose `can_run_code` is `true`, `null` otherwise. The scanner's report as the store records it in evidence (`scanner`, `scanner_version`, `file_name`, `size`, `complete`, `position`, `error`, `globals`), plus `verdict` and `scanned_at` (UTC, `YYYY-MM-DDTHH:MM:SSZ`) |
| `verdict` | `dangerous` if any global is dangerous, else `suspicious` if any is suspicious, else `incomplete` if the scan stopped early, else `clean`. An incomplete scan is never `clean` (FR-022) |
| `record_sha256` | SHA-256 of the UTF-8 JSON of the record without this field, keys sorted, no spaces (`separators=(",", ":")`), non-ASCII kept as is |

The record holds no weight bytes and no personal data, and names files only by the manifest's `path` and
the file's base name. `record_sha256` detects a record changed after it was made; it is a checksum, not a
signature. The record's authority is the reviewed change that brought it.

## Registering from a record

`register MANIFEST.toml --from-record RECORD.json` reads no weight file: the local files need not exist.
It refuses (exit code 1, a message naming the problem, nothing written) when:

- `schema_version` is not `"1"`, `record_sha256` does not match or a field is missing or unknown;
- `model_id` or `manifest_sha256` does not match the manifest, or the list of `location`s is not the
  manifest's local weight files in manifest order;
- a file's `format` and `can_run_code` do not fit its name (for example a `.pt` file claimed as
  `safetensors`): the name allows its own format and, for a name that is not code-free, `pytorch-zip`;
- a file that can run code has no `scan`, a file that cannot run code has one or a scan's `verdict`
  does not follow from its `globals` and `complete`.

Otherwise each local file becomes the inventory entry `register` would have made from the bytes (same
identifier, location, size, format and `can_run_code`), and hub files, the lockfile, the base model and
datasets register as usual. The version records the record's SHA-256 (`registration_record_sha256`).

Each recorded scan is then applied exactly as a check's local scan of the same bytes would be: a
`dangerous` global opens a `weight_file_scan` alert, a `suspicious` one records a `scan_suspicious`
watch event and a scan that stopped early a `scan_incomplete` watch event, with the same cause and
detail. The evidence is the recorded scan (constitution I): `source` `picklescan`, `url`
`registration-record:sha256:<record_sha256>`, `retrieved_at` the recorded `scanned_at`,
`matched_identifier` the file's SHA-256, `detail` with the scanner version and the recorded scan as the
stored body. It belongs to no check run.

## Checking a version registered from a record

`check --source` without `picklescan` reads no local file, so it records nothing about the missing
bytes. With `picklescan` selected, a file of such a version whose bytes are not on this machine gets a
`weight_file_absent` watch event (never an alert) saying so, with the record's SHA-256; the alerts and
watch events from the recorded scan are left as they are. If the bytes are present, they are scanned
as usual.

A newer scanner is applied by recording again where the weights are and registering the new record as
a new version (`register --model-id ID --from-record ...`).
