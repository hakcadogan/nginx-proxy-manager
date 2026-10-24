#!/usr/bin/env python3
"""Extract OWASP CRS SecRule/SecAction catalog (id, msg, file, paranoia, category)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ID_RE = re.compile(r"\bid:(\d+)\b")
MSG_RE = re.compile(r"msg:'([^']*)'|msg:\"([^\"]*)\"")
PL_RE = re.compile(r"paranoia-level/(\d)")
ATTACK_RE = re.compile(r"tag:'attack-([^']+)'")
CRS_TAG_RE = re.compile(r"tag:'OWASP_CRS/([^']+)'")
PHASE_RE = re.compile(r"\bphase:(\d+)\b")


def flatten(text: str) -> str:
    # Join lines ending with backslash continuation
    out: list[str] = []
    buf = ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
        else:
            buf += line
            out.append(buf)
            buf = ""
    if buf:
        out.append(buf)
    return "\n".join(out)


def parse_file(path: Path) -> list[dict]:
    items: list[dict] = []
    flat = flatten(path.read_text(encoding="utf-8", errors="replace"))
    for line in flat.splitlines():
        if "SecRule" not in line and "SecAction" not in line:
            continue
        m = ID_RE.search(line)
        if not m:
            continue
        rid = m.group(1)
        msg_m = MSG_RE.search(line)
        msg = ""
        if msg_m:
            msg = msg_m.group(1) or msg_m.group(2) or ""
        pl_m = PL_RE.search(line)
        pl = int(pl_m.group(1)) if pl_m else 0
        cat_m = ATTACK_RE.search(line)
        category = cat_m.group(1) if cat_m else ""
        if not category:
            crs_m = CRS_TAG_RE.search(line)
            category = crs_m.group(1) if crs_m else ""
        ph_m = PHASE_RE.search(line)
        phase = int(ph_m.group(1)) if ph_m else 0
        # Prefer detectable rules (have msg) but keep skipAfter helpers out of UI noise:
        # include if msg present OR id looks like a primary CRS rule (xxx100+)
        if not msg and (rid.endswith("011") or rid.endswith("012") or "skipAfter" in line):
            continue
        items.append(
            {
                "id": rid,
                "msg": msg or f"CRS rule {rid}",
                "file": path.name,
                "paranoia": pl,
                "category": category or "other",
                "phase": phase,
            }
        )
    return items


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/owasp-crs/rules")
    out_path = Path(sys.argv[2] if len(sys.argv) > 2 else "-")
    files = sorted(root.glob("REQUEST-*.conf")) + sorted(root.glob("RESPONSE-*.conf"))
    seen: set[str] = set()
    items: list[dict] = []
    # NSP built-in rules (overlay)
    for nsp in (
        {
            "id": "1000100",
            "msg": "NSP bad bot User-Agent",
            "file": "nsp-overlay",
            "paranoia": 0,
            "category": "bad-bot",
            "phase": 1,
        },
        {
            "id": "1000090",
            "msg": "NSP UA allowlist skip (bad-bot bypass)",
            "file": "nsp-overlay",
            "paranoia": 0,
            "category": "bad-bot",
            "phase": 1,
        },
    ):
        seen.add(nsp["id"])
        items.append(nsp)
    for f in files:
        for it in parse_file(f):
            if it["id"] in seen:
                continue
            seen.add(it["id"])
            items.append(it)
    items.sort(key=lambda x: (x["file"], int(x["id"])))
    data = {"crs_rules_dir": str(root), "count": len(items), "items": items}
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if str(out_path) == "-":
        sys.stdout.write(text)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        print(f"wrote {len(items)} rules → {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
