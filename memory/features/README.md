# Memory Feature Extraction

This module extracts numerical feature vectors from normalized memory case data for use with the Isolation Forest anomaly detection model.

## Extracted Features

| Feature | Description |
|---------|-------------|
| `process_count` | Total number of processes |
| `powershell_count` | Number of PowerShell-related processes |
| `cmd_count` | Number of cmd.exe processes |
| `suspicious_cmdlines` | Count of command lines with suspicious indicators |
| `external_connections` | Number of non-local network connections |
| `malfind_count` | Number of malfind hits |
| `rwx_regions` | Number of RWX memory regions |
| `lsass_handle_count` | Number of handles to LSASS process |
| `debug_privilege_count` | Number of processes with SeDebugPrivilege |
| `unsigned_dll_count` | Number of DLLs from non-standard paths |

## Pipeline

```
memory_case_schema.json
        ↓
    Feature Extractor
        ↓
    Feature Vector (numerical array)
```

## Status
- [ ] Implement feature extraction functions
- [ ] Add feature normalization/scaling
- [ ] Export feature vectors for training
