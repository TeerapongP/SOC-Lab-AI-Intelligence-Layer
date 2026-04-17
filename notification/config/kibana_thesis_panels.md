# Kibana Thesis Panel Setup (AI SOC Intelligence Dashboard)

Use data view `soc-alerts*` and time field `timestamp`.

## Panel 1: Total Alerts
- Type: Metric
- Metric: Count of records
- Filter (optional): `event_type : "e2e"`

## Panel 2: Priority Distribution
- Type: Pie / Donut
- Slice by: Terms of `priority.keyword`
- Size: Count
- Filter (optional): `event_type : "e2e"`

## Panel 3: Event Trend Over Time (L1)
- Type: Line
- X-axis: Date histogram on `timestamp`
- Y-axis: Count
- Break down by: Terms `priority.keyword`

## Panel 4: L2 Enrich Latency
- Type: Line
- X-axis: Date histogram on `timestamp`
- Y-axis: Average of `response_ms`
- Filter: `layer : "L2"`

## Panel 5: L3 Risk Score Trend
- Type: Line
- X-axis: Date histogram on `timestamp`
- Y-axis: Average of `risk_score`
- Break down by: Terms `anomaly_type.keyword`

## Panel 6: L3 MTTD Timeline
- Type: Line
- X-axis: Date histogram on `timestamp`
- Y-axis: Average of `mttd_s`

## Panel 7: LLM Faithfulness Score
- Type: Gauge
- Metric: Average of `faithfulness_score`
- Filter: `layer : "LLM"`
- Range: 0 to 1

## Panel 8: Latest Events Table
- Type: Data Table
- Sort: `timestamp` desc
- Columns:
  - `timestamp`
  - `event_type`
  - `priority`
  - `source_ip`
  - `risk_score`
  - `anomaly_type`
  - `mitre_tactic`
  - `response_ms`
  - `faithfulness_score`

## Quick Filters (KQL)
- All thesis mock docs: `event_type : "e2e" and source : "mockgen"`
- High only: `priority : "HIGH"`
- LLM only: `layer : "LLM"`
