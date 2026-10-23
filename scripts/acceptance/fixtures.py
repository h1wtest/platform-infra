"""Only explicitly owned event fixtures may be corrected/replayed by acceptance."""
import json
from pathlib import Path
import sys
import uuid
from common import STATE


def save_poison(record):
    uuid.UUID(record['quarantine_id'])
    uuid.UUID(record['run_id'])
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from private_files import atomic_json
    atomic_json(STATE / 'poison.json', record)


def owned_record(records, marker=None):
    marker = marker or json.loads((STATE / 'poison.json').read_text())
    expected = str(uuid.UUID(marker['quarantine_id']))
    selected = [record for record in records if str(record.get('id')) == expected and not record.get('replayed_at')]
    if len(selected) != 1:
        raise AssertionError('Exact owned poison fixture missing or already replayed; unrelated quarantine must never be selected')
    record = selected[0]
    if record.get('topic') != marker['topic'] or int(record.get('partition_id', record.get('partition', -1))) != marker['partition'] or int(record.get('offset_id', record.get('offset', -1))) != marker['offset']:
        raise AssertionError('Owned quarantine identity does not match recorded Kafka coordinates')
    return record
