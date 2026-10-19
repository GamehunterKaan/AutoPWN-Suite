# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Compare two response bodies without letting a hostile body make the comparison quadratic."""

from collections import Counter
from difflib import SequenceMatcher
from time import monotonic

# Rough number of character pairs one search for the longest common block may visit (about a tenth of a second).
# Markup, which is mostly a few characters repeated, and about 20,000 characters of varied text stay under it,
# because difflib ignores the characters that make up more than 1% of a text. Longer varied text is compared on
# its first characters.
WORK_BUDGET = 500_000
# Seconds after which the search for more common blocks stops, so a body that splits into thousands of small
# blocks (a periodic one, for example) cannot keep the scan busy through one comparison.
SECONDS = .5


def _work(left, right):
    """Character pairs one search for the longest common block visits: for each character of the left text, the
    places it occurs in the right text, unless it makes up more than 1% of it (then difflib ignores it)."""
    counts = Counter(right)
    popular = len(right) // 100 + 1 if len(right) >= 200 else len(right)
    return sum(counts[char] for char in left if counts[char] <= popular)


def similarity(left, right):
    """difflib's ratio, bounded in work and in time.

    A body of many different characters (for example 100 KB of random Unicode) leaves difflib nothing to
    ignore, so it compares every character of one text with each place the same character occurs in the other:
    tens of seconds for one search, during which the scan cannot be stopped. Texts that would take one search
    more than WORK_BUDGET are cut to the prefix that fits it (a difference after that prefix is not seen). A
    periodic body makes difflib repeat the search for thousands of small blocks, so the blocks are searched for
    here, as SequenceMatcher.get_matching_blocks does, stopping after SECONDS and counting the blocks found so
    far. Keep this in step with `_similarity` in poc_runtime.py, which downloaded PoCs carry without this package.
    """
    work = _work(left, right)
    while work > WORK_BUDGET and len(left) > 1000:
        # Cutting both texts changes which characters of the right text difflib ignores (more than 1% of it), so
        # the work is measured again on the cut pair and the cut repeated until it fits.
        keep = max(1000, int(len(left) * (WORK_BUDGET / work) ** .5 * .9))
        left, right = left[:keep], right[:keep]
        work = _work(left, right)
    matcher = SequenceMatcher(None, left, right)
    ranges, matched, deadline = [(0, len(left), 0, len(right))], 0, monotonic() + SECONDS
    while ranges and monotonic() < deadline:
        left_start, left_end, right_start, right_end = ranges.pop()
        left_at, right_at, size = matcher.find_longest_match(left_start, left_end, right_start, right_end)
        if size:
            matched += size
            if left_start < left_at and right_start < right_at:
                ranges.append((left_start, left_at, right_start, right_at))
            if left_at + size < left_end and right_at + size < right_end:
                ranges.append((left_at + size, left_end, right_at + size, right_end))
    return 2 * matched / (len(left) + len(right)) if left or right else 1.0
