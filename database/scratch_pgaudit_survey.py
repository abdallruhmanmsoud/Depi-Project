import re
from collections import Counter

# Survey the entire file for unique patterns
cmd_counts   = Counter()
class_counts = Counter()
name_counts  = Counter()
line_types   = Counter()
sample_non_audit = []

total_lines = 0
audit_lines = 0

# Regex for a full single-line audit record
AUDIT_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC) \[(\d+)\] (\w+):\s+AUDIT:\s+(.*)'
)

with open('postgresql.log', 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        total_lines += 1
        line = line.rstrip('\r\n')

        m = AUDIT_RE.match(line)
        if m:
            audit_lines += 1
            payload = m.group(4)
            # Parse CSV-like payload: type,session_id,sub_id,class,command,obj_type,obj_name,sql,param
            parts = payload.split(',', 8)
            if len(parts) >= 5:
                audit_type = parts[0]     # SESSION / OBJECT
                class_     = parts[3]     # READ / WRITE / DDL / ROLE / FUNCTION
                command    = parts[4]     # SELECT / INSERT / UPDATE etc.
                class_counts[class_] += 1
                cmd_counts[command] += 1
                name_counts[audit_type] += 1
        else:
            line_types['non_audit'] += 1
            if len(sample_non_audit) < 10:
                sample_non_audit.append(line)

print(f'Total lines     : {total_lines:,}')
print(f'AUDIT lines     : {audit_lines:,}')
print(f'Non-audit lines : {line_types["non_audit"]:,}')
print()
print('Audit Type (SESSION/OBJECT):')
for k,v in name_counts.most_common(): print(f'  {k}: {v:,}')
print()
print('Class (READ/WRITE/DDL/ROLE):')
for k,v in class_counts.most_common(): print(f'  {k}: {v:,}')
print()
print('Command (top 30):')
for k,v in cmd_counts.most_common(30): print(f'  {k}: {v:,}')
print()
print('Sample non-AUDIT lines:')
for l in sample_non_audit: print(' ', repr(l[:120]))
