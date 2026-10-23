"""User-supplied database credentials remain data in provisioning SQL."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cli


def sql_strings(statement):
    """Decode standard PostgreSQL string literals, rejecting broken boundaries."""
    result = []
    index = 0
    while index < len(statement):
        if statement[index] != "'":
            index += 1
            continue
        index += 1
        value = []
        while index < len(statement):
            if statement[index] == "'":
                if index + 1 < len(statement) and statement[index + 1] == "'":
                    value.append("'")
                    index += 2
                    continue
                index += 1
                result.append(''.join(value))
                break
            value.append(statement[index])
            index += 1
        else:
            raise AssertionError('Unterminated SQL literal')
    return result


class DatabasePasswordBoundaries(unittest.TestCase):
    def test_configured_password_roundtrips_two_sql_literal_layers(self):
        password = "quote'@:#?%/\\-$dollar\nsecond line"
        values = {db + '_' + role + '_password': password for db in cli.manifests.DBS for role in ('migration', 'runtime')}
        calls = []
        with patch.object(cli, 'dbsql', side_effect=lambda statement, database='postgres': calls.append((statement, database))):
            cli.provision_databases(values)
        creates = [statement for statement, database in calls if database == 'postgres']
        for statement in creates:
            literals = sql_strings(statement)
            commands = [item for item in literals if item.startswith('CREATE ROLE ')]
            self.assertEqual(len(commands), 2)
            for command in commands:
                self.assertEqual(sql_strings(command), [password])


if __name__ == '__main__':
    unittest.main()
