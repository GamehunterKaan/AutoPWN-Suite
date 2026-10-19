# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Compare two response bodies without letting a hostile body make the comparison quadratic."""

from collections import Counter
from difflib import SequenceMatcher

# Rough number of character pairs difflib may visit (about a quarter of a second at most). The tens of kilobytes
# of an ordinary page stay under it, because difflib ignores the characters that make up more than 1% of a text,
# which in markup or prose is most of them.
WORK_BUDGET = 500_000


def similarity(left, right):
    """difflib's ratio, on shorter prefixes when the two texts would take it far longer than a page needs.

    A body of many different characters (for example 100 KB of random Unicode) leaves difflib nothing to
    ignore, so it compares every character of one text with each place the same character occurs in the other:
    tens of seconds for one comparison, during which the scan cannot be stopped. Keep this in step with
    `_similarity` in poc_runtime.py, which downloaded PoCs carry without this package.
    """
    counts = Counter(right)
    popular = len(right) // 100 + 1 if len(right) >= 200 else len(right)
    work = sum(counts[char] for char in left if counts[char] <= popular)
    if work > WORK_BUDGET:
        keep = max(1000, int(len(left) * (WORK_BUDGET / work) ** .5))
        left, right = left[:keep], right[:keep]
    return SequenceMatcher(None, left, right).ratio()
