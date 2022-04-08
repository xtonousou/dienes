#! /usr/bin/env python3

import requests

dienes_url = 'http://localhost:8000'
dienes_username = 'dienes_svc'
dienes_password = 'Str0nk_P@ss_H3re'

data = {
    'fqdn': 'name.domain.tld',
    'ip': '10.1.2.3',
}
r = requests.post(dienes_url + '/dns/record/ipv4/add', auth=(dienes_username, dienes_password, ),
                  json=data)
print(r.json())
