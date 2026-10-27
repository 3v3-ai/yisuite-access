"""The one rule for "does this held key grant that wanted key".

Three copies disagreed: the backend grant check matched any raw prefix (so
'bookkeeper.sales' covered 'bookkeeper.salesX'), delegation matched at a dot,
and the frontend matched the other way round. They are now this function, the
same test vectors (contracts/access/key_cover_cases.json) run in pytest and in
the frontend's vitest, and the TypeScript twin in
cloudprofit-react/src/features/auth/keyCover.ts.

A held key grants the wanted key when it is
  1. the same key;
  2. an ancestor at a boundary: the wanted key continues the held one with '.'
     (a child: 'bookkeeper.sales' covers 'bookkeeper.sales.new') or '-' (a
     sibling route of the same family: 'banking.operations.import' covers
     'banking.operations.import-execute'; 45 registered keys rely on this);
     any other continuation does NOT ('bookkeeper.sales' does not cover
     'bookkeeper.salesx');
  3. the wanted key's registered parent.
"""

from __future__ import annotations

from typing import Iterable, Optional

BOUNDARIES = ('.', '-')


def covers(held: Iterable[str], wanted: str, parent: Optional[str] = None) -> bool:
    for h in held:
        if h == wanted:
            return True
        if wanted.startswith(h) and wanted[len(h):len(h) + 1] in BOUNDARIES:
            return True
        if parent is not None and h == parent:
            return True
    return False
