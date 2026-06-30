# Memory Inference

This module runs the trained Isolation Forest model on new memory cases to produce anomaly scores.

## Pipeline

```
New Memory Dump
        ↓
    Volatility Analysis
        ↓
    Normalization (→ memory_case_schema.json)
        ↓
    Feature Extraction (→ feature vector)
        ↓
    Isolation Forest Inference
        ↓
    Anomaly Score + Dashboard Results
```

## Output

```json
{
  "case_id": "case_001",
  "anomaly_score": -0.85,
  "is_anomalous": true,
  "feature_contributions": {
    "malfind_count": 0.35,
    "rwx_regions": 0.28,
    "debug_privilege_count": 0.15,
    "suspicious_cmdlines": 0.12,
    "external_connections": 0.10
  }
}
```

## Status
- [ ] Implement inference pipeline
- [ ] Add feature contribution analysis
- [ ] Integrate with dashboard API
