import re

# Check for multi-line audit records and user field patterns
AUDIT_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC) \[(\d+)\] (\w+):\s+AUDIT:\s+(.*)'
)

# Also check if any AUDIT lines are followed by continuation lines
samples_with_continuation = []
samples_misc = []
prev_was_audit = False
prev_line = ''

with open('postgresql.log', 'r', encoding='utf-8', errors='replace') as f:
    for i, line in enumerate(f):
        line = line.rstrip('\r\n')
        m = AUDIT_RE.match(line)
        if m:
            payload = m.group(4)
            parts = payload.split(',', 8)
            # Show MISC class examples
            if len(parts) >= 4 and parts[3] == 'MISC':
                if len(samples_misc) < 5:
                    samples_misc.append(line[:180])
            prev_was_audit = True
            prev_line = line
        else:
            if prev_was_audit and line.startswith('\t'):
                # Continuation of previous AUDIT line
                samples_with_continuation.append((prev_line[:120], line[:120]))
            prev_was_audit = False
        if i > 50000:
            break

print('MISC class samples:')
for s in samples_misc:
    print(' ', s)
print()
print('Audit lines with continuation (tab-indented next line):')
for p, c in samples_with_continuation[:5]:
    print('  AUDIT:', p)
    print('  CONT :', c)

# Also check the object_name field format
print()
print('Checking object_name field (schema.table):')
count = 0
with open('postgresql.log', 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = AUDIT_RE.match(line.rstrip())
        if m:
            parts = m.group(4).split(',', 8)
            if len(parts) >= 7 and parts[6] and parts[6] != '<none>':
                print(' ', parts[6])
                count += 1
                if count >= 15:
                    break
