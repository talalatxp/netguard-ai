"""Streamlit integration tests for the AI-10 local demo."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import pandas as pd
from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


class StreamlitAppTests(unittest.TestCase):
    def test_app_starts_with_the_frozen_random_hgb_default(self) -> None:
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()

        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.selectbox[0].value, "random:hist_gradient_boosting")
        self.assertEqual(len(app.get("file_uploader")), 1)
        self.assertIn("Recorded test evidence", [item.value for item in app.subheader])

        app.selectbox[0].select("temporal:hist_gradient_boosting").run()

        self.assertEqual(len(app.exception), 0)
        metrics = {metric.label: metric.value for metric in app.metric}
        self.assertEqual(metrics["ATTACK recall"], "5.2%")

    def test_one_valid_row_is_scored_end_to_end(self) -> None:
        summary = json.loads(
            (ROOT / "reports" / "split-summary.json").read_text(encoding="utf-8")
        )
        content = pd.DataFrame(
            [{feature: 0 for feature in summary["feature_names"]}]
        ).to_csv(index=False).encode("utf-8")
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()

        app.get("file_uploader")[0].upload(
            "one-flow.csv", content, "text/csv"
        ).run()

        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(app.error), 0)
        metrics = {metric.label: metric.value for metric in app.metric}
        self.assertEqual(metrics["Rows scored"], "1")
        self.assertEqual(len(app.dataframe), 1)


if __name__ == "__main__":
    unittest.main()
