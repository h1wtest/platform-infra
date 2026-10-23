"""Validate CNPG with the exact release CRD schema, core resources with kubeconform."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request
import jsonschema
import yaml
import cli

path = Path(sys.argv[1])
with urllib.request.urlopen(cli.OPERATOR_URL, timeout=60) as response: content = response.read()
if hashlib.sha256(content).hexdigest() != cli.OPERATOR_SHA256:
    raise RuntimeError('CNPG schema release digest mismatch')
crds = {doc['spec']['names']['kind']: doc for doc in yaml.safe_load_all(content) if doc and doc.get('kind') == 'CustomResourceDefinition'}
resources = json.loads(path.read_text())['items']
core = []
for resource in resources:
    if resource['apiVersion'] == 'postgresql.cnpg.io/v1':
        schema = next(version['schema']['openAPIV3Schema'] for version in crds[resource['kind']]['spec']['versions'] if version['name'] == 'v1')
        jsonschema.Draft7Validator(schema).validate(resource)
    else:
        core.append(resource)
path.with_name('core-resources.json').write_text(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': core}))
print('CNPG resources strictly validated against pinned release CRD schema.')
