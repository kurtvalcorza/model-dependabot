# projects fixtures

Built by hand for feature 003 discovery (research A13); nothing here was downloaded.

`detector/` is a small model project:

- `requirements.lock.txt`: hash-locked (made-up hashes), the format registration accepts.
- `requirements-dev.txt`: not locked; its first line includes `../outside.txt`, outside the
  project, which discovery must never open.
- `pyproject.toml`: one dependency with a range and one VCS dependency.
- `runs/best.safetensors`: a pickle (Python's `pickle.dumps({"step": 1}, protocol=4)`) under a
  code-free name.
- `weights/good.safetensors`: a well-formed safetensors file, a copy of
  `tests/fixtures/manifests/weights/tiny.safetensors`.
- `README.md`: model card front matter with a base model, two hub datasets, a licence, a licence
  link and one key discovery does not read; the base model and datasets are recorded in
  `tests/fixtures/hf_upstream/` so that `discover --upstream` can be replayed.
- `uv.lock`: a lock format this version lists as not read.
- `model.toml`: a manifest naming a different base model, for the comparison.

The parts git cannot hold are made in `tmp_path` by the `detector_project` fixture in
`tests/conftest.py`: a link `link-out` to a directory outside the project (a symbolic link, or a
junction on Windows without the symbolic-link privilege), a requirements file over 1 MiB, a
directory tree deeper than 24 levels and a `.venv/` directory with a weight file in it.
