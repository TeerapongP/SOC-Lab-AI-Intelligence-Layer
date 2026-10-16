import json
from pathlib import Path


def test_dashboards_mark_faithfulness_as_paused():
    root = Path(__file__).resolve().parents[2]
    dashboard_paths = [
        root / "grafana" / "dashboards" / "soc-overview.json",
        root / "notification" / "config" / "soc_overview.json",
    ]

    for path in dashboard_paths:
        dashboard = json.loads(path.read_text(encoding="utf-8"))
        panels = [panel for panel in dashboard["panels"] if "faithfulness" in panel["title"].lower()]
        assert len(panels) == 1
        assert panels[0]["type"] == "text"
        assert "ground truth" in panels[0]["options"]["content"].lower()
        assert "targets" not in panels[0]
