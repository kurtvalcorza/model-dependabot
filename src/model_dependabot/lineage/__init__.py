"""Multi-parent, typed model lineage (feature 011, data-model.md).

A lineage edge links a child model version to one parent: a hub repository at a revision, or a
model id and version registered in the same store. Its relationship is one of ``RELATIONSHIPS``,
read with the child as the subject ("the child is fine-tuned from the parent"), or ``UNSPECIFIED``
when the type is not known (a legacy ``[base_model]`` or an untyped imported ancestor). A manifest
accepts only ``RELATIONSHIPS``; ``UNSPECIFIED`` is internal and cannot be written in one (FR-002).

The modules of this package are pure functions of edge rows: ``edges`` builds and folds them,
``graph`` resolves references and finds lineage problems, ``propagate`` decides which findings of
a registered parent travel to a child.
"""

from __future__ import annotations

RELATIONSHIPS = ("fine-tuned-from", "adapter-for", "merged-from", "quantized-from")
UNSPECIFIED = "unspecified"
EDGE_KINDS = ("hub", "model")
