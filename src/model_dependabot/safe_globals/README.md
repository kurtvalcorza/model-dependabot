# The safe list of pickle globals

`safe-globals.toml` is the list of pickle globals that the strict globals policy accepts without an
exception. Under `policy ID --globals strict`, any global in a scanned pickle file of the model that
is neither on this list nor excepted for that file's SHA-256 is listed in a `globals_policy` alert.
Under the default policy the list is not read.

## Entries

Each entry is `{module, name, why, added_in}`: one global exactly as the scanner reports it, why it is
on the list and the list version that added it.

Every entry MUST be one exact global (module and name); prefixes and wildcards are not allowed.

No entry may have a module or name that contains the lower-case string `unknown` (compared
case-sensitively, as the scanner does): the scanner writes `unknown` for an import it could not
resolve, so such a pair names no import anybody identified. The loader refuses the file if an entry
breaks either rule, has an empty part or appears twice.

## Versions

The file starts with `version`, an integer. Any change to the entries, an addition or a removal,
bumps it by one and adds a `[[changes]]` row (`version`, `date`, `summary`). A unit test holds the
SHA-256 of the entries for each version and fails when the entries change without a new version.
Each `globals_policy` alert cites the version and the SHA-256 of the file as read, so an alert can
always be traced to the list that judged it. When a newer version lists a global, the next check
removes it from open alerts' lists with that version as the recorded cause; when a version removes
one, the next check lists it again.

## Trade-off in version 1

Version 1 holds `_codecs.encode` and `numpy.core.multiarray.scalar` because both appear in ordinary
checkpoints: protocol 2 pickles rebuild every `bytes` value through `_codecs.encode`, and numpy
scalars such as a saved metric go through `numpy.core.multiarray.scalar`. Leaving them off would make
the strict policy raise on nearly every such file.

The cost: `_codecs.encode` can rebuild arbitrary bytes, so a file that lists it can carry any byte
string into whatever else it calls, and `numpy.core.multiarray.scalar` with an object dtype can carry
an arbitrary object. Neither runs code on its own, and the call that would use the bytes or the
object is a separate global that the strict policy still judges, but the list no longer guarantees
that a listed global is inert in every combination. A later version can remove either.
