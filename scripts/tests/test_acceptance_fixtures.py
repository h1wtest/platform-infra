import pathlib
import sys
import unittest
import uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'acceptance'))
from fixtures import owned_record


class AcceptanceFixtureOwnership(unittest.TestCase):
    def test_unrelated_older_quarantine_is_never_selected(self):
        owned = str(uuid.uuid4())
        unrelated = {'id': str(uuid.uuid4()), 'topic': 'identity.events.v1', 'partition': 0, 'offset': 1, 'replayed_at': None}
        current = {'id': owned, 'topic': 'identity.events.v1', 'partition': 2, 'offset': 47, 'replayed_at': None}
        marker = {'run_id': str(uuid.uuid4()), 'quarantine_id': owned, 'topic': 'identity.events.v1', 'partition': 2, 'offset': 47}
        self.assertIs(owned_record([unrelated, current], marker), current)
        self.assertIsNone(unrelated['replayed_at'])
        with self.assertRaises(AssertionError): owned_record([unrelated], marker)
        with self.assertRaises(AssertionError): owned_record([{**current, 'offset': 48}], marker)
        with self.assertRaises(AssertionError): owned_record([{**current, 'replayed_at': '2026-10-23T00:00:00Z'}], marker)


if __name__ == '__main__': unittest.main()
