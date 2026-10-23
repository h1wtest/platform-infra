#!/usr/bin/env python3
import argparse
from pathlib import Path
from e2e import new_user, save_state

parser=argparse.ArgumentParser()
parser.add_argument('--base',default='https://localhost:8448')
parser.add_argument('--mailpit',default='http://localhost:28026')
parser.add_argument('--ca',required=True)
parser.add_argument('--state',required=True)
args=parser.parse_args()
client,account=new_user(args,'load')
client.call('POST','/api/v1/auth/logout',{})
save_state(Path(args.state),{'probe':account})
print('Disposable load account registered, email verified and Kafka profile observed; rate limits unchanged')
