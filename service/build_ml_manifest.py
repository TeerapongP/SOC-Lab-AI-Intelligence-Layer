from __future__ import annotations

import argparse
import json
from pathlib import Path

EXCLUDED_MARKERS = (
    "dataset_cleaned_parquet_smoke",
    "run_outputs",
    "__tmp",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create an ML-ready manifest from cleaning summary.")
    parser.add_argument("--summary", default=r"E:\thesis\dataset\dataset_cleaned_parquet\_cleaning_summary.json")
    parser.add_argument("--output-summary", default=r"E:\thesis\dataset\dataset_cleaned_parquet\_ml_ready_summary.json")
    parser.add_argument("--output-files", default=r"E:\thesis\dataset\dataset_cleaned_parquet\_ml_ready_files.txt")
    return parser.parse_args()


def is_ml_ready(result: dict) -> bool:
    value = f"{result.get('file', '')} {result.get('output', '')}".lower()
    return not any(marker in value for marker in EXCLUDED_MARKERS)


def main() -> None:
    args = parse_args()
    summary_path = Path(args.summary)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    results = [result for result in summary.get("results", []) if is_ml_ready(result)]

    ml_summary = {
        "source_summary": str(summary_path),
        "total_files": len(results),
        "successful_files": sum(1 for result in results if not result.get("error")),
        "failed_files": sum(1 for result in results if result.get("error")),
        "total_rows": sum(int(result.get("rows") or 0) for result in results),
        "total_input_mb": round(sum(float(result.get("input_mb") or 0.0) for result in results), 6),
        "total_output_mb": round(sum(float(result.get("output_mb") or 0.0) for result in results), 6),
        "excluded_markers": list(EXCLUDED_MARKERS),
        "results": results,
    }

    output_summary = Path(args.output_summary)
    output_files = Path(args.output_files)
    output_summary.write_text(json.dumps(ml_summary, indent=2), encoding="utf-8")
    output_files.write_text(
        "\n".join(str(result.get("output", "")) for result in results if result.get("output")),
        encoding="utf-8",
    )
    print(f"Wrote {output_summary}")
    print(f"Wrote {output_files}")


if __name__ == "__main__":
    main()
