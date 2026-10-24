# Contract: model manifest (additions)

Feature 001's [manifest contract](../../001-inventory-alerts/contracts/manifest.md) stands. This feature adds
two optional dataset keys.

```toml
[[datasets]]
doi = "10.5281/zenodo.20066074"
paper_doi = ["10.1177/1758835919874651"]   # optional: papers the owner ties to this dataset

[[datasets]]
hub = "hf:datasets/owner/name"               # a dataset on the hub, without a DOI
revision = "0123abcd…"                       # exact commit; required for a pinned entry
```

## Rules

- A `[[datasets]]` table has either `doi` or `hub`, not both. Both is an error (exit code 1). Neither is the
  gap "no DOI", as in feature 001: registration never fails because of a gap.
- `paper_doi` is a list of DOIs. The service checks them for retractions (FR-004) and never infers them.
- A `hub` dataset without `revision` is a gap ("no revision") and is not checked, as for 001's hub weight files.
- Licences are not written in the manifest: the service records what each source declares (FR-008).
- 001's rules stand: unknown keys are an error; registration never fails because of a gap.
