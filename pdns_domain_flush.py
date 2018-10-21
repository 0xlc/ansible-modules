#!/usr/bin/env python

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: pdns_domain_flush

short_description: Just an experiment to practice with Python

description:
    - "PowerDNS Server - Flush the positive, negative and packet cache for a given domain name"

options:
    domain:
        description:
            - Domain to flush
        required: true
    state:
        description:
            - There is only 'flushed' available.
        required: false
    pdns_host:
        description:
            - PowerDNS server ip/localhost
        required: true
    pdns_port:
        description:
            - PowerDNS server port (default 8081)
        required: false
    pdns_proto:
        description:
            - http PowerDNS protocol (default http)
        required: false
    pdns_api_key:
        description:
            - PowerDNS server API Key
        required: yes
    timeout:
        description:
            - Set a custom timeout if needed (default 10 seconds)
        required: false

author:
    - Luca (@0xlc)
'''

EXAMPLES = '''
# Flush domain example.com
- name: Test pdns_domain_flush
  pdns_domain_flush:
    domain: 'example.com'
    pdns_host: 127.0.0.1
    pdns_api_key: 'examplekey'
'''

from ansible.module_utils.basic import AnsibleModule
import requests
import json


def domain_flusher(domain, proto, host,
                   port, api_key, timeout):
    headers = {'X-API-Key': api_key}
    url = "{}://{}:{}/api/v1/servers/localhost/cache/flush".format(
        proto, host, port)
    payload = {'domain': domain + '.'}  # '.' is needed to avoid error 'Domain is not canonical'
    try:
        r = requests.put(url, headers=headers, params=payload, timeout=timeout)
    except requests.exceptions.RequestException as err:
        text_result, status_code = err, None
        return (text_result, status_code)

    text_result, status_code = r.text, r.status_code
    return (text_result, status_code)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            domain=dict(type='str', required=True),
            state=dict(type='str', default='flushed', choices=['flushed']),
            pdns_host=dict(type='str', required=True),
            pdns_port=dict(type='int', default=8081),
            pdns_proto=dict(type='str', default='http', choices=['http', 'https']),
            pdns_api_key=dict(type='str', required=True),
            timeout=dict(type='int', default=10),
        )
    )

    req_result = domain_flusher(
        module.params['domain'],
        module.params['pdns_proto'],
        module.params['pdns_host'],
        module.params['pdns_port'],
        module.params['pdns_api_key'],
        module.params['timeout'],)

    if req_result[1] in [200, 201, 204]:  # req_result[1] = status_code
        req_to_json = json.loads(req_result[0])  # req_result[0] = text_result
        if req_to_json['count'] > 0:
            module.exit_json(changed=True)
        else:
            module.exit_json(changed=False)
    else:
        module.fail_json(msg='Error message: {}'.format(req_result[0]))


if __name__ == '__main__':
    main()
