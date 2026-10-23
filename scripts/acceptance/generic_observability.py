#!/usr/bin/env python3
"""Prove actual generic-owner HTTPS traces, durable event causality and scraped metrics.

Local HTTPS payment fixture only, never NOWPayments/Telegram/provider acceptance.
Run after the parent rebuilds/deploys telemetry. No cluster mutations or fault injection.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import json
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from e2e import Client, NoRedirect, eventually, find_mail, save_state
from generic_commerce import command

INFRA = Path(__file__).resolve().parents[2]
LOCAL = INFRA / '.generic-local'
ACCEPTANCE = LOCAL / 'acceptance'
NAMESPACE = 'generic-subscriptions'
CONTEXT = 'k3d-sso-remediation'
OWNERS = {'catalog': ('catalog', 'catalog-service:8006'),
          'billing': ('billing-service', 'billing-service:8007'),
          'subscription': ('subscription', 'subscription-service:8008'),
          'referral': ('referral', 'referral-service:8009')}
METRICS = ('http_requests_total', 'http_request_duration_seconds_bucket',
           'http_request_duration_seconds_count', 'http_request_duration_seconds_sum',
           'outbox_pending', 'outbox_oldest_pending_age_seconds',
           'kafka_sampled_committed_lag', 'kafka_sampled_committed_lag_timestamp_seconds')
LIMITS = [
    'Explicit local HTTPS payment fixture; no NOWPayments or Telegram acceptance.',
    'No production HA, multi-host resilience, real-provider latency or throughput claim.',
    'Checkout HTTP trace is not asserted to parent the background payment worker: no durable order trace contract.',
    'Legacy audit v2 consumer parents the durable envelope origin, not the Kafka publisher header; no producer-parent claim.',
    'Catalog publishes but consumes no topic; consumer lag is required only for billing/subscription/referral.',
    'kafka.publish is the platformkit durable-outbox publisher span (not legacy outbox.publish).',
]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def private_file(path):
    require(path.is_file() and not path.is_symlink(), 'private regular input required')
    require(os.name == 'nt' or path.stat().st_mode & 0o077 == 0, 'private input must be owner-only')


def guard(args):
    require(args.base == 'https://localhost:18448' and args.fixture == 'https://localhost:19444'
            and args.mailpit == 'http://localhost:38026' and args.tempo == 'http://localhost:33200'
            and args.prometheus == 'http://localhost:39090', 'only exact task-local origins allowed')
    require(args.kubeconfig.resolve() == (LOCAL / 'kubeconfig.json').resolve(),
            'explicit task-private kubeconfig required')
    require(args.credentials.resolve() == (ACCEPTANCE / 'credentials.json').resolve(),
            'explicit task-private owner credential input required')
    for path in (args.kubeconfig, args.credentials):
        private_file(path)
    require(args.ca.resolve() == (LOCAL / 'ca.crt').resolve()
            and args.fixture_ca.resolve() == args.ca.resolve(), 'task CA required for both HTTPS origins')
    require(args.ca.is_file() and not args.ca.is_symlink(), 'regular explicit CA required')
    for path in (args.private_state, args.evidence):
        require(path.parent.resolve() == ACCEPTANCE.resolve() and not path.exists() and not path.is_symlink(),
                'choose NEW output files directly inside ignored task acceptance directory')
    require(args.private_state.resolve() != args.evidence.resolve(), 'private state and sanitized evidence must differ')
    config = json.loads(args.kubeconfig.read_text(encoding='utf-8'))
    require(config.get('current-context') == CONTEXT and len(config.get('contexts', [])) == 1
            and config['contexts'][0]['name'] == CONTEXT and len(config.get('clusters', [])) == 1,
            'one explicitly selected local context required')
    context = config['contexts'][0]['context']
    require(context.get('namespace', NAMESPACE) == NAMESPACE
            and context['cluster'] == config['clusters'][0]['name'], 'generic namespace/context required')
    cluster = config['clusters'][0]['cluster']
    server = urllib.parse.urlsplit(cluster.get('server', ''))
    require(server.scheme == 'https' and server.hostname in ('localhost', '127.0.0.1', '::1')
            and not server.username and not server.password and not server.query and not server.fragment
            and not cluster.get('insecure-skip-tls-verify') and bool(cluster.get('certificate-authority-data')),
            'strict embedded-CA loopback cluster required')
    for user in config.get('users', []):
        require(not any(key in user.get('user', {}) for key in ('exec', 'auth-provider')),
                'external credential plugins forbidden')
    base = ['kubectl', '--kubeconfig', str(args.kubeconfig), '--context', CONTEXT,
            '--namespace', NAMESPACE, '--request-timeout=15s']
    environment = {key: value for key, value in os.environ.items()
                   if key in ('PATH', 'HOME', 'SYSTEMROOT', 'WINDIR', 'TMPDIR', 'TEMP', 'TMP')}
    def kube(*words):
        result = subprocess.run(base + list(words), text=True, capture_output=True,
                                timeout=25, env=environment)
        require(result.returncode == 0, 'isolated read-only kubectl guard failed (output withheld)')
        return json.loads(result.stdout)
    require(kube('get', 'namespace', NAMESPACE, '-o', 'json')['metadata']['name'] == NAMESPACE,
            'task namespace absent')
    actual_ca = kube('get', 'secret', 'platform-ca', '-o', 'json')['data']['ca.crt']
    require(base64.b64decode(actual_ca, validate=True) == args.ca.read_bytes(),
            'task namespace trust root differs from explicit HTTPS CA')
    return kube


class TraceHeader(urllib.request.BaseHandler):
    value = None

    def https_request(self, request):
        if self.value:
            request.add_header('Traceparent', self.value)
        return request


class TracedClient(Client):
    def __init__(self, args):
        super().__init__(args.base, str(args.ca))
        self.trace_header = TraceHeader()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(args.ca))),
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect(), self.trace_header)

    def traced(self, owner, method, path, route, body=None, *, expected=(200,)):
        trace_id, parent_id = secrets.token_hex(16), secrets.token_hex(8)
        self.trace_header.value = '00-' + trace_id + '-' + parent_id + '-01'
        try:
            status, result, headers = self.call(method, path, body, expected=expected)
        finally:
            self.trace_header.value = None
        returned = next((value for key, value in headers.items() if key.lower() == 'traceparent'), '')
        parts = returned.split('-')
        require(len(parts) == 4 and parts[0] == '00' and parts[1] == trace_id
                and re.fullmatch('[0-9a-f]{16}', parts[2]) and int(parts[3], 16) & 1,
                'operation did not return matching sampled server traceparent')
        return result, {'owner': owner, 'service': OWNERS[owner][0], 'method': method,
                        'route': route, 'status': status, 'trace_id': trace_id,
                        'injected_parent_span_id': parent_id, 'server_span_id': parts[2]}


def hex_id(value, size):
    require(isinstance(value, str), 'malformed OTLP identifier')
    if re.fullmatch('[0-9a-fA-F]{' + str(size * 2) + '}', value):
        result = value.lower()
    else:
        result = base64.b64decode(value, validate=True).hex()
    require(len(result) == size * 2 and int(result, 16) != 0, 'invalid OTLP identifier')
    return result


def kind(value):
    return {'SPAN_KIND_INTERNAL': 1, 'SPAN_KIND_SERVER': 2, 'SPAN_KIND_CLIENT': 3,
            'SPAN_KIND_PRODUCER': 4, 'SPAN_KIND_CONSUMER': 5}.get(value, value)


def safe_route(value):
    return (isinstance(value, str) and len(value) <= 180
            and (value in ('unmatched', '/') or re.fullmatch(
                r'(?:(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE|OTHER) )?/[A-Za-z0-9_/{*}.\-]*', value))
            and not re.search(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-', value))


def trace_spans(data, trace_id):
    """Retain only structural IDs, bounded instrumentation names and safe HTTP fields."""
    spans = []
    for batch in data.get('batches', data.get('resourceSpans', [])):
        service = next((attribute['value'].get('stringValue')
                        for attribute in batch.get('resource', {}).get('attributes', [])
                        if attribute.get('key') == 'service.name'), '')
        require(isinstance(service, str) and re.fullmatch('[a-z][a-z0-9-]{0,63}', service),
                'noncanonical trace resource service')
        for scope in batch.get('scopeSpans', batch.get('instrumentationLibrarySpans', [])):
            for span in scope.get('spans', []):
                require(hex_id(span['traceId'], 16) == trace_id, 'Tempo returned unrelated trace')
                name = span.get('name', '')
                require(safe_route(name) or re.fullmatch(r'(?:GET|POST|PUT|PATCH|DELETE) http.client', name)
                        or name in ('kafka.publish', 'kafka.process', 'outbox.publish', 'delivery.email', 'delivery.telegram', 'http.request')
                        or re.fullmatch(r'kafka.process [a-z_.]+', name) or name in ('GET http', 'POST http'),
                        'unexpected/unbounded span name (withheld)')
                status = span.get('status', {}).get('code', 0)
                clean = {'service': service, 'trace_id': trace_id, 'name': name,
                         'kind': kind(span.get('kind', 0)), 'span_id': hex_id(span['spanId'], 8),
                         'parent_span_id': hex_id(span['parentSpanId'], 8) if span.get('parentSpanId') else None,
                         'links': [{'trace_id': hex_id(link['traceId'], 16),
                                    'span_id': hex_id(link['spanId'], 8)} for link in span.get('links', [])],
                         'status': status, 'http': {}}
                for attribute in span.get('attributes', []):
                    key, value = attribute.get('key'), attribute.get('value', {})
                    if key == 'http.route':
                        route = value.get('stringValue')
                        require(safe_route(route), 'unbounded HTTP span route (withheld)')
                        clean['http']['route'] = route
                    elif key == 'http.request.method' or service == 'identity-service' and key == 'http.method':
                        method = value.get('stringValue')
                        require(method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'OTHER'),
                                'unbounded HTTP method')
                        clean['http']['method'] = method
                    elif key == 'http.response.status_code':
                        code = int(value.get('intValue', value.get('stringValue', 0)))
                        require(100 <= code <= 599, 'invalid HTTP span status')
                        clean['http']['status'] = code
                    elif service == 'identity-service' and name == 'http.request' and key in (
                            'code.file.path', 'code.module.name', 'code.line.number', 'thread.id',
                            'thread.name', 'target', 'busy_ns', 'idle_ns'):
                        # Rust tracing adds technical source/thread metadata.
                        # Observe only parent IDs; never persist these values.
                        continue
                    else:
                        raise RuntimeError('unexpected trace attribute (key/value withheld)')
                spans.append(clean)
    return sorted(spans, key=lambda span: (span['service'], span['span_id']))


class Observer:
    def __init__(self, args, evidence, kube=None):
        self.args, self.evidence, self.kube = args, evidence, kube
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def json(self, url):
        with self.opener.open(urllib.request.Request(url, headers={'Accept': 'application/json'}), timeout=10) as response:
            require(response.status == 200, 'observability endpoint failed')
            return json.load(response)

    def inventory(self):
        require(self.kube is not None, 'guarded pod inventory required')
        replicas = self.kube('get', 'replicasets', '-o', 'json')['items']
        pods = self.kube('get', 'pods', '-o', 'json')['items']
        result = {}
        for owner, (_, service_target) in OWNERS.items():
            app = service_target.split(':')[0]
            deployment = self.kube('get', 'deployment', app, '-o', 'json')
            replica_uids = {replica['metadata']['uid'] for replica in replicas
                            if any(reference.get('controller') is True
                                   and reference.get('kind') == 'Deployment'
                                   and reference.get('uid') == deployment['metadata']['uid']
                                   for reference in replica['metadata'].get('ownerReferences', []))}
            selected = [pod for pod in pods if any(reference.get('controller') is True
                        and reference.get('kind') == 'ReplicaSet' and reference.get('uid') in replica_uids
                        for reference in pod['metadata'].get('ownerReferences', []))
                        and not pod['metadata'].get('deletionTimestamp')]
            require(len(selected) == deployment['spec']['replicas'] and len(selected) >= 2,
                    owner + ': stable replicated Deployment inventory required')
            result[owner] = {}
            for pod in selected:
                metadata, status = pod['metadata'], pod.get('status', {})
                name, uid = metadata['name'], metadata['uid']
                require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,252}', name)
                        and re.fullmatch(r'[0-9a-f-]{36}', uid), 'invalid pod identity')
                containers = status.get('containerStatuses', [])
                require(status.get('phase') == 'Running' and containers
                        and all(container.get('ready') and container.get('state', {}).get('running')
                                for container in containers), owner + ': all replicas must be ready')
                address = status.get('podIP', '')
                require(re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', address), 'DNS A pod IP required')
                result[owner][name] = {'uid': uid, 'instance': address + ':' + service_target.rsplit(':', 1)[1],
                                      'restart_counts': {
                    container['name']: container.get('restartCount', 0) for container in containers}}
        return result

    def trace(self, operation, publish=False, consume=False, dependency=False):
        last = []
        def observed():
            nonlocal last
            try:
                data = self.json(self.args.tempo + '/api/traces/' + operation['trace_id'])
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    return None
                raise
            last = trace_spans(data, operation['trace_id'])
            operation['spans'] = last
            save_state(self.args.evidence, self.evidence)
            server = next((span for span in last if span['span_id'] == operation['server_span_id']
                           and span['service'] == operation['service'] and span['kind'] == 2
                           and span['parent_span_id'] == operation['injected_parent_span_id']
                           and span['http'] == {'method': operation['method'], 'route': operation['route'],
                                                'status': operation['status']}), None)
            if not server:
                return None
            clients = [span for span in last if span['service'] == operation['service']
                       and span['kind'] == 3 and span['parent_span_id'] == server['span_id']
                       and 200 <= span['http'].get('status', 0) < 300]
            if not clients:
                return None
            if dependency and not any(span['service'] == 'catalog' and span['kind'] == 2
                                      and span['parent_span_id'] in {client['span_id'] for client in clients}
                                      and span['http'].get('route') == 'GET /internal/v2/catalog/offers/{id}'
                                      and span['http'].get('status') == 200 for span in last):
                return None
            publishers = [span for span in last if span['service'] == operation['service']
                          and span['kind'] == 4 and span['name'] == 'kafka.publish'
                          and span['parent_span_id'] == server['span_id']
                          and {'trace_id': operation['trace_id'], 'span_id': server['span_id']} in span['links']
                          and span['status'] in (1, 'STATUS_CODE_OK')]
            if publish and not publishers:
                return None
            event_type = {
                'POST /api/v1/admin/catalog/revisions/{id}/publish': 'catalog.revision_published',
                'PUT /api/v1/admin/referrals/partners/{id}/rate': 'referral.rate_changed',
                'POST /api/v1/admin/payments/{id}/reverify': 'billing.payment_reviewed',
                'POST /api/v1/subscriptions/{id}/cancel': 'subscription.changed',
                'POST /api/v1/subscriptions/{id}/resume': 'subscription.changed',
            }.get(operation['route'])
            if publish and not any(span['service'] == 'admin-audit-service'
                                   and span['name'] == 'kafka.process ' + event_type
                                   and span['parent_span_id'] == server['span_id']
                                   and span['status'] in (1, 'STATUS_CODE_OK') for span in last):
                return None
            if consume and not any(span['service'] == 'billing-service' and span['kind'] == 5
                                   and span['name'] == 'kafka.process'
                                   and span['parent_span_id'] in {publisher['span_id'] for publisher in publishers}
                                   and {'trace_id': operation['trace_id'], 'span_id': server['span_id']} in span['links']
                                   and span['status'] in (1, 'STATUS_CODE_OK') for span in last):
                return None
            return last
        eventually('actual operation trace causality: ' + operation['owner'] + ' ' + operation['route'],
                   observed, timeout=self.args.wait_seconds)
        operation['causality'] = {'server_parent': True, 'successful_http_client': True,
                                  'durable_outbox_parent_and_link': publish,
                                  'billing_consumer_parent_and_origin_link': consume,
                                  'legacy_audit_consumer_envelope_origin_parent': publish,
                                  'catalog_dependency_client_parent': dependency}
        save_state(self.args.evidence, self.evidence)

    def targets(self):
        data = self.json(self.args.prometheus + '/api/v1/targets')['data']['activeTargets']
        result = {}
        for owner, (_, service_target) in OWNERS.items():
            service = service_target.split(':')[0]
            selected = [target for target in data if target.get('labels', {}).get('job') == 'platform'
                        and target.get('labels', {}).get('owner') == owner]
            expected = {pod['instance'] for pod in self.evidence['metrics_pods_baseline'][owner].values()}
            require(len(selected) == len(expected) and {target['labels'].get('instance') for target in selected} == expected,
                    owner + ': Prometheus must discover every distinct ready replica')
            for target in selected:
                labels = target['labels']
                require(set(labels) == {'job', 'app', 'service', 'owner', 'instance'}
                        and labels['app'] == service and labels['service'] == service
                        and target.get('health') == 'up', owner + ': canonical healthy per-pod scrape required')
            result[owner] = sorted(expected)
        return result

    def metrics(self):
        expression = '{job="platform",owner=~"' + '|'.join(OWNERS)
        expression += '",__name__=~"' + '|'.join(METRICS) + '"}'
        data = self.json(self.args.prometheus + '/api/v1/query?' + urllib.parse.urlencode({'query': expression}))
        require(data.get('status') == 'success' and data['data']['resultType'] == 'vector',
                'real Prometheus instant vector required')
        rows = []
        for row in data['data']['result']:
            labels = row['metric']
            require(set(labels) <= {'__name__', 'instance', 'job', 'app', 'service', 'owner',
                                    'method', 'route', 'status', 'le', 'topic', 'partition'},
                    'unexpected metric labels (withheld)')
            owner = labels.get('owner')
            require(owner in OWNERS and labels.get('app') == OWNERS[owner][1].split(':')[0]
                    and labels.get('service') == labels['app'] and labels.get('__name__') in METRICS
                    and labels.get('job') == 'platform', 'metric query returned unrelated target')
            require(labels.get('instance') in {pod['instance'] for pod in self.evidence['metrics_pods_baseline'][owner].values()},
                    'metric target is not an inventoried ready task pod')
            if 'route' in labels:
                require(safe_route(labels['route']), 'unbounded metric route (withheld)')
            if 'topic' in labels:
                require(re.fullmatch(r'(identity|profile|notification|catalog|billing|subscription|referral|external)\.events\.v[12]', labels['topic']),
                        'unbounded consumer topic label')
                require(re.fullmatch(r'[0-9]{1,5}', labels.get('partition', '')), 'unbounded partition label')
            if 'status' in labels:
                require(re.fullmatch(r'[1-5][0-9]{2}', labels['status']), 'unbounded status label')
            if 'method' in labels:
                require(labels['method'] in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'OTHER'),
                        'unbounded method label')
            if 'le' in labels:
                require(labels['le'] in ('0.005', '0.01', '0.025', '0.05', '0.1', '0.25', '0.5', '1', '2.5', '5', '10', '+Inf'),
                        'unbounded histogram bucket label')
            number = float(row['value'][1])
            require(math.isfinite(number) and number >= 0, 'invalid metric value')
            rows.append({'labels': labels, 'value': number, 'sample_time': float(row['value'][0])})
        require(len(rows) <= 12000, 'unexpected HTTP metric cardinality')
        return rows


def metric_value(rows, name, instance, **labels):
    return sum(row['value'] for row in rows if row['labels'].get('__name__') == name
               and row['labels'].get('instance') == instance
               and all(row['labels'].get(key) == value for key, value in labels.items()))


def prove_metrics(observer, baseline, operations, started):
    expected = Counter((operation['owner'], operation['method'], operation['route'], str(operation['status']))
                       for operation in operations)

    def selected(rows, owner, name, **labels):
        return [row for row in rows if row['labels'].get('owner') == owner
                and row['labels'].get('__name__') == name
                and all(row['labels'].get(key) == value for key, value in labels.items())]

    def ready():
        require(observer.inventory() == observer.evidence['metrics_pods_baseline'],
                'pod UID/IP/readiness/restart changed during acceptance; fresh baseline required')
        targets = observer.targets()
        rows = observer.metrics()
        observer.evidence['metrics_observed'] = rows
        observer.evidence['metrics_targets_observed'] = targets
        save_state(observer.args.evidence, observer.evidence)
        # Never count a replacement pod or reset as a new-series increase.
        prior = {tuple(sorted(row['labels'].items())): row['value'] for row in baseline
                 if row['labels']['__name__'].startswith('http_')}
        current = {tuple(sorted(row['labels'].items())): row['value'] for row in rows
                   if row['labels']['__name__'].startswith('http_')}
        require(all(identity in current and current[identity] >= value for identity, value in prior.items()),
                'HTTP counter/histogram reset or retired series; fresh stable baseline required')
        deltas = []
        for (owner, method, route, status), count in expected.items():
            labels = {'method': method, 'route': route, 'status': status}
            entry = {'owner': owner, **labels, 'exercised': count, 'deltas': {}, 'per_pod_deltas': {}}
            for name, extra in (('http_requests_total', {}), ('http_request_duration_seconds_count', {}),
                                ('http_request_duration_seconds_bucket', {'le': '+Inf'})):
                by_pod = {}
                for instance in targets[owner]:
                    before = metric_value(baseline, name, instance, **labels, **extra)
                    after = metric_value(rows, name, instance, **labels, **extra)
                    require(after >= before, 'counter reset cannot supply exercised increase')
                    by_pod[instance] = after - before
                entry['deltas'][name] = sum(by_pod.values())
                entry['per_pod_deltas'][name] = by_pod
                if entry['deltas'][name] < count:
                    return None
            for instance in targets[owner]:
                count_value = metric_value(rows, 'http_requests_total', instance, **labels)
                if not count_value:
                    continue
                buckets = sorted((float(row['labels']['le']), row['value']) for row in
                                 selected(rows, owner, 'http_request_duration_seconds_bucket', instance=instance, **labels))
                if (len(buckets) != 12 or buckets[-1][1] != count_value
                        or any(left[1] > right[1] for left, right in zip(buckets, buckets[1:]))
                        or metric_value(rows, 'http_request_duration_seconds_count', instance, **labels) != count_value
                        or not selected(rows, owner, 'http_request_duration_seconds_sum', instance=instance, **labels)):
                    return None
            deltas.append(entry)
        gauges = {}
        for owner in OWNERS:
            gauges[owner] = {}
            for name in ('outbox_pending', 'outbox_oldest_pending_age_seconds'):
                matches = selected(rows, owner, name)
                if (len(matches) != len(targets[owner])
                        or {row['labels']['instance'] for row in matches} != set(targets[owner])
                        or any(row['sample_time'] < started for row in matches)):
                    return None
                # Every replica queries the same authoritative owner database;
                # max retains the worst observed age/count rather than doubling it.
                gauges[owner][name] = {'maximum': max(row['value'] for row in matches), 'per_pod': matches}
            if gauges[owner]['outbox_oldest_pending_age_seconds']['maximum'] > 60:
                return None
        for owner, topic in (('billing', 'subscription.events.v1'), ('subscription', 'billing.events.v1'),
                             ('referral', 'billing.events.v1')):
            lag = selected(rows, owner, 'kafka_sampled_committed_lag', topic=topic)
            stamps = selected(rows, owner, 'kafka_sampled_committed_lag_timestamp_seconds', topic=topic)
            observations, fresh = [], []
            for row in lag:
                pair = [stamp for stamp in stamps if stamp['labels']['instance'] == row['labels']['instance']
                        and stamp['labels']['partition'] == row['labels']['partition']]
                if len(pair) != 1 or pair[0]['value'] > time.time() + 5:
                    return None
                entry = {'instance': row['labels']['instance'], 'partition': row['labels']['partition'],
                         'topic': topic, 'lag': row['value'], 'observed_at': pair[0]['value'],
                         'age_seconds': max(0, time.time() - pair[0]['value']),
                         'observed_during_run': pair[0]['value'] >= started}
                observations.append(entry)
                if entry['observed_during_run']:
                    fresh.append(entry)
            # Idle/unassigned partitions do not invent samples. Keep every
            # assigned replica's actual samples and identify fresh work exactly.
            if not fresh:
                return None
            gauges[owner]['consumer_lag'] = {'observed_partition_samples': observations,
                                            'fresh_partition_samples': fresh,
                                            'replicas_without_topic_samples': sorted(set(targets[owner]) -
                                                {row['labels']['instance'] for row in lag})}
        return {'http_exercised_deltas': deltas, 'outbox_and_consumer_gauges': gauges,
                'stable_ready_replica_targets': targets}
    result = eventually('real Prometheus per-pod leaf route/status/histogram deltas and actual committed lag',
                        ready, timeout=observer.args.wait_seconds)
    observer.evidence['metrics_proof'] = result
    observer.evidence['checks'].append('prometheus_all_replica_scrapes_actual_exercised_deltas_no_resets_and_fresh_committed_lag')


def run(args):
    kube = guard(args)
    credentials = json.loads(args.credentials.read_text(encoding='utf-8'))
    require(all(isinstance(credentials.get(key), str) and credentials[key]
                for key in ('owner_email', 'owner_password', 'owner_totp_secret', 'fixture_control_token')),
            'existing owner MFA and fixture control credential required')
    private = {'accounts': [], 'records': {}, 'fixture_only': True}
    evidence = {'status': 'RUNNING', 'fixture_only': True, 'namespace': NAMESPACE, 'checks': [],
                'operations': [], 'limits': LIMITS, 'transaction': {}}
    save_state(args.private_state, private)
    save_state(args.evidence, evidence)
    observer = Observer(args, evidence, kube)
    stage = 'owner_authentication'
    try:
        owner = TracedClient(args)
        owner.login(credentials['owner_email'], credentials['owner_password'], credentials['owner_totp_secret'])
        authority = owner.call('GET', '/api/v1/auth/me')[1]['user']
        require('owner' in authority['roles'] and authority['mfa_verified'], 'existing owner MFA authority required')
        stage = 'stable_per_pod_metrics_baseline'
        evidence['metrics_pods_baseline'] = observer.inventory()
        save_state(args.evidence, evidence)
        evidence['metrics_targets_baseline'] = eventually('all ready pod targets discovered and scraped',
                                                         observer.targets, timeout=args.wait_seconds)
        baseline = observer.metrics()
        started = time.time()
        evidence['metrics_started_at'] = started
        evidence['metrics_baseline'] = baseline
        save_state(args.evidence, evidence)

        def traced(client, owner_name, method, path, route, body=None, expected=(200,)):
            value, operation = client.traced(owner_name, method, path, route, body, expected=expected)
            evidence['operations'].append(operation)
            save_state(args.evidence, evidence)
            return value

        def register(label, referral_code=None):
            client = TracedClient(args)
            client.bootstrap_csrf()
            account = {'label': label, 'email': 'generic-telemetry-' + uuid.uuid4().hex + '@example.invalid',
                       'password': secrets.token_urlsafe(24) + 'aA9!', 'locale': 'en'}
            body = {key: account[key] for key in ('email', 'password', 'locale')}
            if referral_code:
                body['referral_code'] = referral_code
            result = client.call('POST', '/api/v1/auth/register', body, expected=(201,))[1]
            account['user_id'] = result['user_id']
            private['accounts'].append(account)
            save_state(args.private_state, private)
            code = find_mail(args.mailpit, account['email'], 'verification')
            client.call('POST', '/api/v1/auth/verify-email', {'user_id': account['user_id'], 'code': code})
            client.login(account['email'], account['password'])
            eventually('new telemetry account profile', lambda: client.call('GET', '/api/v1/users/me')[1].get('profile'))
            return client, account

        stage = 'new_referral_accounts'
        referrer, referrer_account = register('referrer')
        def summary():
            value = referrer.call('GET', '/api/v1/referrals', expected=(200, 503))[1]
            return value if value.get('code') and 'earned' in value else None
        before = eventually('actual disposable referral account', summary)
        # Customer summary intentionally omits private override/rate-version
        # fields; the MFA-authorized paginated partner listing exposes them.
        cursor = None
        seen_cursors = set()
        partner = None
        for _ in range(100):
            query = {'limit': 100}
            if cursor:
                query['cursor'] = cursor
            page = owner.call('GET', '/api/v1/admin/referrals/partners?' + urllib.parse.urlencode(query))[1]
            partner = next((item for item in page['items'] if item['user_id'] == referrer_account['user_id']), None)
            if partner:
                break
            cursor = page.get('next_cursor')
            if not cursor:
                break
            require(cursor not in seen_cursors, 'admin partner pagination repeated cursor')
            seen_cursors.add(cursor)
        require(partner is not None, 'new referrer absent from bounded admin partner listing')
        traced(owner, 'referral', 'PUT', '/api/v1/admin/referrals/partners/' + referrer_account['user_id'] + '/rate',
               'PUT /api/v1/admin/referrals/partners/{id}/rate', command(rate_bps=1000,
               expected_version=partner['rate_version'], reason='Disposable local telemetry partner rate'))
        customer, _ = register('customer', before['code'])

        stage = 'new_catalog_publication'
        product = owner.call('POST', '/api/v1/admin/catalog/products',
                             command(key='telemetry-' + uuid.uuid4().hex[:16]), expected=(201,))[1]
        plan = owner.call('POST', '/api/v1/admin/catalog/products/' + product['id'] + '/plans',
                          command(key='standard', upgrade_rank=1), expected=(201,))[1]
        draft = owner.call('POST', '/api/v1/admin/catalog/plans/' + plan['id'] + '/drafts',
                           command(expected_version=plan['version']), expected=(201,))[1]
        draft = owner.call('PUT', '/api/v1/admin/catalog/revisions/' + draft['id'], command(
            expected_version=draft['version'], name={'en': 'Telemetry acceptance', 'ru': 'Приёмка телеметрии'},
            description={'en': 'Disposable telemetry transaction', 'ru': 'Временная приёмочная транзакция'},
            features=[{'key': 'access', 'label': {'en': 'Access', 'ru': 'Доступ'}}],
            offers=[{'duration_days': 30, 'price': '10.000000', 'currency': 'USDT'}]))[1]
        revision = traced(owner, 'catalog', 'POST', '/api/v1/admin/catalog/revisions/' + draft['id'] + '/publish',
                          'POST /api/v1/admin/catalog/revisions/{id}/publish', command(expected_version=draft['version']))
        private['records'].update(product_id=product['id'], offer_id=revision['offers'][0]['id'])
        save_state(args.private_state, private)

        stage = 'sampled_checkout_and_payment'
        order = traced(customer, 'billing', 'POST', '/api/v1/orders', 'POST /api/v1/orders',
                       command(offer_id=revision['offers'][0]['id'], kind='INITIAL', network='USDTTRC20'), expected=(202,))
        private['records']['order_id'] = order['id']
        save_state(args.private_state, private)
        def created():
            current = customer.call('GET', '/api/v1/orders/' + order['id'])[1]
            return current if current['payment_attempt'].get('provider_payment_id') else None
        order = eventually('actual HTTPS fixture payment creation', created, timeout=args.wait_seconds)
        payment_id = order['payment_attempt']['provider_payment_id']
        require(isinstance(payment_id, str) and int(payment_id) > 2**53, 'exact fixture provider payment identifier required')
        # This authentic authoritative mutation emits billing.payment_reviewed under
        # its own sampled HTTP context. It does not pretend to trace the worker.
        for attempt in range(8):
            order = customer.call('GET', '/api/v1/orders/' + order['id'])[1]
            reviewed = traced(owner, 'billing', 'POST', '/api/v1/admin/payments/' + order['id'] + '/reverify',
                              'POST /api/v1/admin/payments/{id}/reverify', command(expected_version=order['version'],
                              reason='Disposable local telemetry reverify'), expected=(200, 409))
            if evidence['operations'][-1]['status'] == 200:
                break
            require(reviewed.get('code') == 'version_conflict', 'reverify rejected for non-version reason')
            time.sleep(0.25)
        else:
            raise RuntimeError('bounded reverify version races did not settle')
        fixture = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(args.fixture_ca))))
        request = urllib.request.Request(args.fixture + '/_fixture/payments/' + payment_id,
            data=json.dumps({'payment_status': 'finished', 'actually_paid': '10.000000', 'send_callback': True}).encode(),
            method='POST', headers={'Content-Type': 'application/json', 'X-Fixture-Control': credentials['fixture_control_token']})
        with fixture.open(request, timeout=15) as response:
            settlement = json.load(response)
        require(settlement.get('fixture') is True and settlement.get('provider_acceptance') is False
                and settlement.get('callback_status') == 202 and settlement.get('create_count_for_order') == 1,
                'actual fixture HTTPS settlement/callback required')
        def fulfilled():
            current = customer.call('GET', '/api/v1/orders/' + order['id'])[1]
            return current if current['state'] == 'FULFILLED' else None
        order = eventually('successful fixture transaction through real Kafka fulfillment', fulfilled, timeout=args.wait_seconds)
        subscription_id = order['subscription_id']
        sub = customer.call('GET', '/api/v1/subscriptions/' + subscription_id)[1]
        require(sub['state'] == 'ACTIVE' and customer.call('GET', '/api/v1/subscriptions/' + subscription_id + '/entitlement')[1]['allowed'],
                'fulfilled order must grant a real active entitlement')
        commission = eventually('actual exact disposable referral commission',
                               lambda: (value if (value := summary()) and value['earned'] == '1.000000' else None),
                               timeout=args.wait_seconds)
        require(commission['available'] == '1.000000', 'referral earned/available mismatch')
        private['records'].update(subscription_id=subscription_id, provider_payment_id=payment_id)
        save_state(args.private_state, private)
        evidence['transaction'] = {'order_id': order['id'], 'subscription_id': subscription_id,
                                   'state': 'FULFILLED', 'subscription_state': 'ACTIVE', 'entitlement_allowed': True,
                                   'referral_earned': '1.000000', 'fixture_callback_status': 202,
                                   'fixture_create_count': 1}
        evidence['checks'].append('successful_real_https_fixture_payment_kafka_fulfillment_entitlement_commission')
        save_state(args.evidence, evidence)

        stage = 'sampled_subscription_mutations'
        cancelled = traced(customer, 'subscription', 'POST', '/api/v1/subscriptions/' + subscription_id + '/cancel',
                           'POST /api/v1/subscriptions/{id}/cancel', command(expected_version=sub['version']))
        require(cancelled['cancel_at_period_end'] is True, 'actual cancel mutation failed')
        resumed = traced(customer, 'subscription', 'POST', '/api/v1/subscriptions/' + subscription_id + '/resume',
                         'POST /api/v1/subscriptions/{id}/resume', command(expected_version=cancelled['version']))
        require(resumed['cancel_at_period_end'] is False, 'actual resume mutation failed')
        traced(referrer, 'referral', 'GET', '/api/v1/referrals', 'GET /api/v1/referrals')
        traced(referrer, 'referral', 'GET', '/api/v1/referrals/payouts', 'GET /api/v1/referrals/payouts')
        # A real bounded 404 adds non-success status/histogram evidence without
        # mutating any other user's record or injecting an infrastructure fault.
        traced(customer, 'subscription', 'GET', '/api/v1/subscriptions/' + str(uuid.uuid4()),
               'GET /api/v1/subscriptions/{id}', expected=(404,))

        stage = 'tempo_actual_operation_causality'
        for operation in evidence['operations']:
            route = operation['route']
            publish = operation['status'] < 300 and (route.endswith('/publish') or route.endswith('/rate')
                       or route.endswith('/reverify') or route.endswith('/cancel') or route.endswith('/resume'))
            observer.trace(operation, publish=publish,
                           consume=operation['owner'] == 'subscription' and publish,
                           dependency=route == 'POST /api/v1/orders')
        evidence['checks'].extend(['actual_sampled_http_client_catalog_dependency_parents',
                                   'all_four_owner_durable_outbox_publish_origin_parents_and_links',
                                   'all_four_owner_legacy_audit_consumers_parent_actual_envelope_origin',
                                   'subscription_mutation_to_billing_kafka_consumer_parent_and_origin_link'])
        stage = 'prometheus_exercised_metrics'
        prove_metrics(observer, baseline, evidence['operations'], started)
        evidence['status'] = 'PASS'
        save_state(args.evidence, evidence)
        print('PASS generic local observability: real transaction, operation-specific causal traces, scraped metric deltas')
        print('LIMIT: local HTTPS fixture only; no checkout-to-background-worker continuity or production HA claim')
    except Exception as error:
        evidence.update(status='FAIL', failed_stage=stage, failure_type=type(error).__name__)
        save_state(args.evidence, evidence)
        raise RuntimeError('generic observability failed at ' + stage + '; sanitized evidence retained; type=' + type(error).__name__) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://localhost:18448')
    parser.add_argument('--mailpit', default='http://localhost:38026')
    parser.add_argument('--fixture', default='https://localhost:19444')
    parser.add_argument('--tempo', default='http://localhost:33200')
    parser.add_argument('--prometheus', default='http://localhost:39090')
    parser.add_argument('--ca', required=True, type=Path)
    parser.add_argument('--fixture-ca', required=True, type=Path)
    parser.add_argument('--credentials', required=True, type=Path)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--private-state', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--wait-seconds', type=int, default=120)
    args = parser.parse_args()
    if not 30 <= args.wait_seconds <= 240:
        parser.error('bounded telemetry/transaction wait must be between 30 and 240 seconds')
    try:
        run(args)
    except Exception as error:
        # Never print urllib exceptions, response bodies, owner secrets or raw OTLP.
        print('FAIL generic local observability; diagnostic_type=' + type(error).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
