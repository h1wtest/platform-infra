#!/usr/bin/env python3
"""Prove one actual trace crosses HTTP/outbox/Kafka/notification/provider work."""
import argparse
import json
import secrets
import urllib.request
from pathlib import Path
from e2e import Client, eventually

from common import ROOT, STATE
root=ROOT
parser=argparse.ArgumentParser();parser.add_argument('--ca',required=True);args=parser.parse_args()
account=json.loads((STATE/'load.json').read_text())['probe']
client=Client('https://localhost:8448',args.ca);client.bootstrap_csrf()
trace_id=secrets.token_hex(16);parent=secrets.token_hex(8)
body=json.dumps({'email':account['email'],'password':account['password'],'device_name':'Correlated trace acceptance'}).encode()
request=urllib.request.Request(client.base+'/api/v1/auth/login',data=body,method='POST',headers={
    'Content-Type':'application/json','Origin':client.base,'X-CSRF-Token':client.csrf,
    'Traceparent':'00-'+trace_id+'-'+parent+'-01'})
with client.opener.open(request,timeout=15) as response:
    assert response.status==200 and json.load(response)['status']=='authenticated'
client.bootstrap_csrf()
def observed():
    req=urllib.request.Request('http://localhost:23200/api/traces/'+trace_id,headers={'Accept':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=10) as response:data=json.load(response)
    except urllib.error.HTTPError as error:
        if error.code==404:return None
        raise
    spans=[]
    for batch in data.get('batches',data.get('resourceSpans',[])):
        attributes=batch.get('resource',{}).get('attributes',[])
        service=next((a['value'].get('stringValue') for a in attributes if a.get('key')=='service.name'),'unknown')
        for scope in batch.get('scopeSpans',batch.get('instrumentationLibrarySpans',[])):
            for span in scope.get('spans',[]):spans.append({'service':service,'name':span.get('name'),'span_id':span.get('spanId'),'parent_span_id':span.get('parentSpanId')})
    services={span['service'] for span in spans};names={span['name'] for span in spans}
    if {'identity-service','profile-service','admin-audit-service','notification-service','notification-worker'}.issubset(services) and 'outbox.publish' in names and 'delivery.email' in names:return spans
    return None
spans=eventually('one real trace with identity/outbox/Kafka/notification/delivery',observed,90)
client.call('POST','/api/v1/auth/logout',{})
print(json.dumps({'trace_id':trace_id,'observed_spans':spans},indent=2))
print('PASS same actual trace correlates HTTP authoritative login, outbox publish, Kafka consumer and delivery worker')
