import sys, os
sys.path.insert(0, 'parser')
from mysqlbinlog_parser import MysqlBinlogParser, build_summary

parser = MysqlBinlogParser()
events = parser.parse_file('all_binlogs.txt')

print('=== VALIDATION CHECKS ===')
print('Total events:', len(events))
print()

expected = [
    ('BINLOG',          '4',   '',          ''),
    ('CREATE_DATABASE', '107', 'wordpress', ''),
    ('CREATE_USER',     '202', 'mysql',     'wpuser@localhost'),
    ('GRANT',           '322', 'mysql',     'wpuser@localhost'),
    ('GRANT',           '591', 'wordpress', 'wpuser@localhost'),
    ('GRANT',           '732', 'wordpress', 'wpuser@localhost'),
]

all_pass = True
for i, (ev, exp) in enumerate(zip(events, expected), 1):
    et, lp, db, user = exp
    checks = [
        ('event_type', ev['event_type'], et),
        ('log_pos',    ev['log_pos'],    lp),
        ('database',   ev['database'],   db),
        ('user',       ev['user'],       user),
    ]
    ok = all(got == want for _, got, want in checks)
    if not ok:
        all_pass = False
        print('Event #' + str(i) + ': FAIL')
        for field, got, want in checks:
            if got != want:
                print('  ' + field + ': got=' + repr(got) + ' want=' + repr(want))
    else:
        print('Event #' + str(i) + ': PASS  [' + et + ']')

print()
print('Timestamps (events 2-6):')
for ev in events[1:]:
    print('  log_pos=' + ev['log_pos'] + '  ts=' + ev['timestamp'])

print()
summary = build_summary(events)
print('Summary:', summary)
print()
print('Overall:', 'ALL PASS' if all_pass else 'SOME FAILURES')
