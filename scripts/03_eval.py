"""
Phase 0 / Step 3: compare LLM verifier output (data/verified.json) against
the hand-labeled ground truth (eval/labels.json) and report agreement.

Labels are matched to verified candidates by (basename, line), not the full
relative path. Full-path matching breaks depending on what directory was
passed as --target when scanning (e.g. the repo root vs. its src/ subfolder
changes whether "src/" ends up as a path prefix) -- basename + a small line
tolerance is robust to that without caring which root was used.

Usage:
    python scripts/03_eval.py
"""
from pathlib import PureWindowsPath

from common import LABELS_PATH, VERIFIED_PATH, load_json

LINE_TOLERANCE = 2


def basename(path: str) -> str:
    return PureWindowsPath(path.replace("/", "\\")).name


def find_match(label: dict, verified: list[dict]):
    label_basename = basename(label["file"])
    candidates = [
        v for v in verified
        if basename(v["sink_file"]) == label_basename
        and abs(v["sink_line"] - label["line"]) <= LINE_TOLERANCE
    ]
    return candidates[0] if candidates else None


def main():
    labels = load_json(LABELS_PATH)
    verified = load_json(VERIFIED_PATH)

    total = 0
    matched = 0
    agree = 0
    rows = []

    for label in labels:
        total += 1
        v = find_match(label, verified)
        if v is None:
            rows.append((label["file"], label["line"], label["expected_reachable"], "NOT FOUND", "-"))
            continue
        matched += 1
        got = v["finding"].get("reachable")
        ok = "match" if got == label["expected_reachable"] else "MISMATCH"
        if got == label["expected_reachable"]:
            agree += 1
        rows.append((label["file"].split("/")[-1], label["line"], label["expected_reachable"], got, ok))

    col_widths = [40, 6, 10, 10, 10]
    header = ["file", "line", "expected", "got", "result"]
    print(" | ".join(h.ljust(w) for h, w in zip(header, col_widths)))
    print("-" * (sum(col_widths) + 3 * (len(col_widths) - 1)))
    for row in rows:
        print(" | ".join(str(c).ljust(w) for c, w in zip(row, col_widths)))

    print()
    print(f"labels: {total}  |  matched to a candidate: {matched}  |  agreement: {agree}/{matched if matched else 1}"
          f" ({(agree / matched * 100) if matched else 0:.0f}%)")
    if matched < total:
        print(f"WARNING: {total - matched} labeled locations were not found in verified.json "
              f"-- Semgrep may have missed them, or the ruleset differs from the one used to build labels.json")


if __name__ == "__main__":
    main()
