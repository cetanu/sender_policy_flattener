# coding=utf-8
"""Writes on-disk change artifacts (JSON diff, HTML diff, BIND format).

Intended for pipelines that want a file-based record of an SPF change plus a
non-zero exit code to flag for review, instead of (or alongside) an email.
"""

import json
from pathlib import Path

from sender_policy_flattener.formatting import (
    format_records_as_bind_text,
    render_diff_html,
    SourceMap,
)

# Type Aliases
Domain = str
SPFRecord = str


def write_change_report(
    report_dir: str,
    zone: Domain,
    prev_addrs: list[SPFRecord],
    curr_addrs: list[SPFRecord],
    prev_sources: SourceMap | None = None,
    curr_sources: SourceMap | None = None,
) -> None:
    out_dir = Path(report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    html, _ = render_diff_html(zone, prev_addrs, curr_addrs, prev_sources, curr_sources)
    (out_dir / f"{zone}.diff.html").write_text(html)
    (out_dir / f"{zone}.bind.txt").write_text(format_records_as_bind_text(curr_addrs))
    (out_dir / f"{zone}.json").write_text(
        json.dumps(
            {
                "previous": prev_addrs,
                "current": curr_addrs,
                "previous_sources": prev_sources or {},
                "current_sources": curr_sources or {},
            },
            indent=4,
            sort_keys=True,
        )
    )
