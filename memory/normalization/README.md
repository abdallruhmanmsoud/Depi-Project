# Memory Normalization Layer

This module converts raw Volatility plugin outputs (pslist, cmdline, dlllist, handles, privs, netscan, malfind) into the normalized JSON schema format defined in `../schema/`.

## Pipeline

```
Raw Volatility Output (CSV/JSON/Text)
        ↓
    Parser (per plugin)
        ↓
    Schema Validation
        ↓
    memory_case_schema.json
```

## Usage

```python
from normalizer import MemoryNormalizer

normalizer = MemoryNormalizer()
case_data = normalizer.normalize_case(
    case_id="case_001",
    volatility_output_dir="path/to/volatility/outputs"
)
```

## Status
- [ ] Implement parsers for each Volatility plugin
- [ ] Add schema validation
- [ ] Add error handling for malformed outputs
