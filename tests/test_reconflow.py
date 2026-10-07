import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import reconflow as rf


def sample_data():
    return rf.build_report_data(
        domain="example.com",
        subs=["a.example.com", "b.example.com"],
        live=[
            {"host": "a.example.com", "url": "https://a.example.com", "status": 200,
             "title": "A Site", "tech": ["nginx"]},
        ],
        scan_host="a.example.com",
        scan_output="22/tcp open ssh\n80/tcp open http",
        nuclei_findings=[
            {"template": "exposed-panel", "name": "Exposed Admin Panel",
             "severity": "info", "matched": "https://a.example.com/admin"},
        ],
        emails=["admin@example.com"],
    )


def test_merge_dedupe_sorts_and_dedupes():
    result = rf.merge_dedupe(["b.com", "a.com", "a.com", "c.com"])
    assert result == ["a.com", "b.com", "c.com"]


def test_merge_dedupe_empty():
    assert rf.merge_dedupe([]) == []


def test_build_report_data_shape():
    data = sample_data()
    assert data["domain"] == "example.com"
    assert len(data["subdomains"]) == 2
    assert data["live_hosts"][0]["status"] == 200
    assert "generated" in data


def test_render_markdown_contains_key_sections():
    md = rf.render_markdown(sample_data())
    assert "# ReconFlow Report — example.com" in md
    assert "a.example.com" in md
    assert "22/tcp open ssh" in md
    assert "Exposed Admin Panel" in md
    assert "admin@example.com" in md


def test_render_markdown_no_scan_host_omits_scan_section():
    data = sample_data()
    data["scan_host"] = None
    data["nuclei_findings"] = []
    md = rf.render_markdown(data)
    assert "## Port Scan" not in md
    assert "## Nuclei Findings" not in md


def test_render_json_round_trips():
    data = sample_data()
    parsed = json.loads(rf.render_json(data))
    assert parsed["domain"] == data["domain"]
    assert parsed["emails"] == data["emails"]


def test_render_html_escapes_and_includes_data():
    data = sample_data()
    data["live_hosts"][0]["title"] = "<script>alert(1)</script>"
    html = rf.render_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "example.com" in html


def test_write_reports_all_formats(tmp_path):
    data = sample_data()
    out_base = tmp_path / "report"
    written = rf.write_reports(data, str(out_base), "all")
    assert len(written) == 3
    for path in written:
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0


def test_write_reports_single_format(tmp_path):
    data = sample_data()
    out_base = tmp_path / "report"
    written = rf.write_reports(data, str(out_base), "md")
    assert len(written) == 1
    assert written[0].endswith(".md")
