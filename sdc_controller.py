import requests

ODL_URL = 'http://localhost:8181/restconf/config/opendaylight-inventory:nodes'

def add_flow_rule(switch, match, actions):
    data = {
        'flow-node-inventory:flow': [
            {
                'id': '0',
                'match': {
                    'ipv4-destination': match,
                },
                'instructions': {
                    'instruction': [
                        {
                            'order': '0',
                            'apply-actions': {
                                'action': [
                                    {
                                        'order': '0',
                                        'output-action': {
                                            'output-node-connector': actions
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                },
                'priority': '10',
                'table_id': '0',
            }
        ]
    }
    url = ODL_URL + f'/node/{switch}/static-flow-pusher:flow/0'
    resp = requests.put(url, auth=('admin', 'admin'), headers={'Content-type': 'application/json'}, json=data)
    if not resp.ok:
        print(f'Error adding flow rule to switch {switch}: {resp.text}')

def remove_flow_rule(switch, match):
    url = ODL_URL + f'/node/{switch}/static-flow-pusher:flow/0?match={match}'
    resp = requests.delete(url, auth=('admin', 'admin'))
    if not resp.ok:
        print(f'Error removing flow rule from switch {switch}: {resp.text}')