#!/usr/bin/python3
"""Open the GTK scenario against the existing, explicitly synthetic local stack."""
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler, Request

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

opener = build_opener(ProxyHandler({}), NoRedirect())
def fetch(url, data=None):
    req = Request(url, data=data, headers={'Content-Type':'application/json'})
    with opener.open(req, timeout=5) as response:
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError('response too large')
        return json.loads(body)

try:
    health = fetch('http://127.0.0.1:8090/v1/health')
    genesis = fetch('http://127.0.0.1:18899',json.dumps({'jsonrpc':'2.0','id':1,'method':'getGenesisHash'}).encode())['result']
    if (health.get('status') != 'ok' or health.get('registryId') != 'demo.synthetic.local'
            or health.get('cluster') != 'solana:local' or health.get('genesisHash') != genesis
            or genesis in ('EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG','5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d')):
        raise ValueError('local profile identity mismatch')
    token = hashlib.sha256(b'demo.synthetic.local').hexdigest()[:24]
    runtime = Path.home()/'.local/state/onelayer-devnet-demo/local-validator/namespaces'/token/'runtime'
    if not (runtime/'admin-credentials.json').is_file():
        raise ValueError('local credentials unavailable')
except Exception:
    sys.exit('Local demo unavailable. Start ./deploy/devnet-demo/live-demo local first.')

env = os.environ.copy()
env.update(ONELAYER_REGISTRY_ID='demo.synthetic.local',ONELAYER_PUBLICATION_CLUSTER='solana:local',
           ONELAYER_RPC_GENESIS_HASH=genesis,ONELAYER_DEMO_RUNTIME_DIR=str(runtime),ONELAYER_ADMIN_ACCESS_LAB='1')
repo = Path(__file__).resolve().parents[3]
entry = 'workflow_demo_smoke.py' if sys.argv[1:] == ['--check-scenario'] else 'native.py'
os.execve('/usr/bin/python3',['/usr/bin/python3',str(repo/'apps/desktop/lab'/entry)],env)
