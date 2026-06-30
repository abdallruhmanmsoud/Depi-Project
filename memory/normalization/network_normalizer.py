"""
Network Normalizer
Parses Volatility 3 windows.netscan.NetScan output.

Expected header:
  Offset  Proto  LocalAddr  LocalPort  ForeignAddr  ForeignPort  State  PID  Owner  Created
"""

from normalization.utils import (
    is_valid_data_line, is_header_line,
    safe_str, safe_int, read_lines,
)


class NetworkNormalizer:

    HEADER_START = "Offset\tProto"
    MIN_COLUMNS = 8

    def normalize(self, filepath: str) -> list:

        print(f"[INFO] Parsing {filepath}")

        results = []
        lines = read_lines(filepath)
        header_found = False

        for line in lines:

            if not header_found:
                if is_header_line(line, self.HEADER_START):
                    header_found = True
                continue

            if not is_valid_data_line(line):
                continue

            parts = line.strip().split("\t")

            if len(parts) < self.MIN_COLUMNS:
                continue

            try:
                pid = int(parts[7])
            except ValueError:
                continue

            results.append({
                "offset": safe_str(parts[0]),
                "protocol": parts[1].strip(),
                "local_addr": safe_str(parts[2]),
                "local_port": safe_int(parts[3]),
                "foreign_addr": safe_str(parts[4]),
                "foreign_port": safe_int(parts[5]),
                "state": safe_str(parts[6]),
                "pid": pid,
                "owner": safe_str(parts[8]) if len(parts) > 8 else "",
                "created": safe_str(parts[9]) if len(parts) > 9 else "",
            })

        print(f"[INFO] Parsed {len(results)} network records")
        return results
