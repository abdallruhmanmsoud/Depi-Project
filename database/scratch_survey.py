import re, collections

name_counts = collections.Counter()
cmd_counts  = collections.Counter()
fields_seen = set()

bytes_read = 0
max_bytes  = 5 * 1024 * 1024  # first 5 MB

with open('audit.log', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        bytes_read += len(line.encode('utf-8'))
        stripped = line.strip()

        m = re.match(r'NAME="([^"]+)"', stripped)
        if m: name_counts[m.group(1)] += 1

        m = re.match(r'COMMAND_CLASS="([^"]+)"', stripped)
        if m: cmd_counts[m.group(1)] += 1

        m = re.match(r'([A-Z_]+)=', stripped)
        if m: fields_seen.add(m.group(1))

        if bytes_read >= max_bytes:
            break

print('NAME values (first 5MB):')
for k,v in name_counts.most_common():
    print('  ' + k + ': ' + str(v))
print()
print('COMMAND_CLASS values (top 40):')
for k,v in cmd_counts.most_common(40):
    print('  ' + k + ': ' + str(v))
print()
print('All XML attribute names seen:')
print(sorted(fields_seen))
