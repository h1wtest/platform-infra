"""Await only transient TCP/policy realization; never retry SQL/schema/auth/TLS failures."""
SCRIPT = '''
set -eu
attempt=0
while [ "$attempt" -lt 20 ]; do
  if PGCONNECT_TIMEOUT=2 psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -Atqc 'SELECT 1' > /tmp/database-result 2>/tmp/database-error; then
    test "$(cat /tmp/database-result)" = 1
    printf 'Verified database connection established before migration.\\n'
    exit 0
  fi
  case "$(cat /tmp/database-error)" in
    *"Connection refused"*|*"connection refused"*|*"Connection timed out"*|*"timeout expired"*|*"could not translate host name"*)
      attempt=$((attempt + 1))
      sleep 1
      ;;
    *)
      printf 'Database gate failed with nontransient authentication, TLS or SQL error; details suppressed to protect DSN.\\n' >&2
      exit 1
      ;;
  esac
done
printf 'Database TCP/network-policy realization deadline exceeded.\\n' >&2
exit 1
'''


def attach(spec, images):
    main = spec['containers'][0]
    database = next(entry for entry in main['env'] if entry['name'] == 'DATABASE_URL')
    spec['initContainers'] = [{'name': 'verified-database-gate', 'image': images['postgres'], 'command': ['/bin/sh', '-ec', SCRIPT], 'env': [database], 'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}}, 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}, 'volumeMounts': [{'name': 'postgres-ca', 'mountPath': '/run/postgres', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}]}]
