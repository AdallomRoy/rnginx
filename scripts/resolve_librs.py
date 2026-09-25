#!/usr/bin/env python3
"""Resolve merge conflicts in crates/ngx-http/src/lib.rs (or similar module lists).
For each conflict hunk: if both sides have the same number of lines, pick per line the
non-`stubs::` version; otherwise take the union preserving order (pub mod lines)."""
import re, sys
p = sys.argv[1] if len(sys.argv) > 1 else 'crates/ngx-http/src/lib.rs'
s = open(p).read()
out = []
i = 0
lines = s.split('\n')
while i < len(lines):
    if lines[i].startswith('<<<<<<<'):
        j = i + 1; ours = []
        while not lines[j].startswith('======='):
            ours.append(lines[j]); j += 1
        j += 1; theirs = []
        while not lines[j].startswith('>>>>>>>'):
            theirs.append(lines[j]); j += 1
        if len(ours) == len(theirs) and all(a.strip().split('::')[-1] == b.strip().split('::')[-1] for a, b in zip(ours, theirs)):
            for a, b in zip(ours, theirs):
                out.append(b if a.strip().startswith('stubs::') and not b.strip().startswith('stubs::') else a)
        else:
            merged = list(ours)
            for b in theirs:
                if b not in merged:
                    merged.append(b)
            out.extend(merged)
        i = j + 1
    else:
        out.append(lines[i]); i += 1
open(p, 'w').write('\n'.join(out))
print('resolved', p)
