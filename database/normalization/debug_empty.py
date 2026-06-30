import json
from collections import Counter

with open('normalized/normalized_events.json','r',encoding='utf-8') as f:
    events = json.load(f)

unknowns = [e for e in events if e['event_type']=='UNKNOWN']
empty_sql = [e for e in unknowns if not e['sql']]
print('Empty-SQL UNKNOWN events:', len(empty_sql))
print()

# Group by header_type
ht_counts = Counter(str(e['header_type']) for e in empty_sql)
print('Header types in empty-SQL UNKNOWN events:')
for ht, c in ht_counts.most_common():
    print('  ' + str(ht) + ' : ' + str(c))

print()
# Show sample of each header type
seen = set()
for e in empty_sql:
    ht = str(e['header_type'])
    if ht not in seen:
        seen.add(ht)
        print('Sample  header_type=' + ht + '  event_id=' + str(e['event_id']) + '  ts=' + str(e['timestamp']))
