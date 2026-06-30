import json

with open('normalized/normalized_events.json','r',encoding='utf-8') as f:
    events = json.load(f)

unknowns = [e for e in events if e['event_type']=='UNKNOWN']
print('Total UNKNOWN:', len(unknowns))
print()

# Show first 15 unknown events
for ev in unknowns[:15]:
    sql = str(ev['sql'] or '')[:80]
    eid = ev['event_id']
    db  = ev['database']
    print('  #' + str(eid) + '  db=' + str(db) + '  sql=' + sql)

print()
# Count sql first words in unknowns
from collections import Counter
first_words = Counter()
for ev in unknowns:
    s = str(ev['sql'] or '').strip()
    fw = s.split()[0].upper() if s else '(empty)'
    first_words[fw] += 1

print('UNKNOWN SQL first words:')
for w, c in first_words.most_common(20):
    print('  ' + w + ' : ' + str(c))
