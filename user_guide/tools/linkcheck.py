#!/usr/bin/env python3
"""Check relative .md links and #anchors in an mdBook src tree."""
import re, sys, pathlib

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "src")
link_re = re.compile(r"\]\(([^)\s]+)\)")
head_re = re.compile(r"^(#{1,6})\s+(.*?)\s*$")


def slug(text: str) -> str:
    # mdBook: strip inline code/markup, lowercase, non-alnum -> '-', collapse
    text = re.sub(r"[`*_\[\]]", "", text)
    text = text.lower()
    text = re.sub(r"[^a-z0-9 _-]", "", text)
    return re.sub(r"\s+", "-", text.strip())


anchors: dict[pathlib.Path, set[str]] = {}
for md in root.rglob("*.md"):
    s = set()
    for line in md.read_text().splitlines():
        m = head_re.match(line)
        if m:
            s.add(slug(m.group(2)))
    anchors[md.resolve()] = s

errors = 0
for md in sorted(root.rglob("*.md")):
    for n, line in enumerate(md.read_text().splitlines(), 1):
        for target in link_re.findall(line):
            if re.match(r"[a-z]+:", target):
                continue
            path, _, frag = target.partition("#")
            dest = (md.parent / path).resolve() if path else md.resolve()
            if path and not dest.exists():
                print(f"{md}:{n}: missing file {target}")
                errors += 1
            elif frag and frag not in anchors.get(dest, set()):
                print(f"{md}:{n}: missing anchor {target}")
                errors += 1
print(f"{errors} broken link(s)")
sys.exit(1 if errors else 0)
