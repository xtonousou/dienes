# dienes

<p align="center"><img width=50% src="media/logo.png"></img></p>
<p align="center">Simple & Async API to add, update and remove DNS records to/from MS Windows DNS Server</p>

---

## Installation

> Currently tested on Rocky Linux 8.5

### System Prerequisites

Run all the below commands as **root** user

```bash
dnf module install -y python39
dnf module reset -y redis
dnf module install -y redis:6
dnf module reset -y nginx
dnf module install -y nginx:1.20
dnf install -y gcc krb5-devel gssntlmssp python39-devel
```

Clone the repo from main branch
```bash
git clone --depth 1 https://github.com/xtonousou/dienes.git /opt/dienes
```

Create service account
```bash
useradd --system --no-create-home --comment "Dienes Service Account" dienes
```

Create celery directories and apply permissions
```bash
mkdir -vp /var/log/dienes /var/run/dienes
chown -R dienes:nginx /opt/dienes
chown -R dienes:dienes /var/log/dienes /var/run/dienes
```

### Python Prerequisites

```bash
python3 -m pip install -r requirements.txt
```

## Configuration

### Redis

Redis have to run locally alongside with `dienes` server

```bash
yes | cp -v etc/redis/redis.conf /etc/redis.conf
systemctl enable --now redis
```

### Hashicorp Vault

If there is no Hashicorp Vault available, read the documentation [here](https://www.vaultproject.io/docs/install) to install it.

Enable a kv2 engine with name `secret` and create the required secrets defined in the schema `etc/hashicorp_vault/vault_schema`.
Then, create the proper ACL named `dienes_ro` which is defined in `etc/hashicorp_vault/vault.hcl`.

Finally, create the token that will be used by `dienes`

```bash
vault login  # login with your root token
vault token create -type=service -renewable=true -orphan=true -display-name="Dienes API Server" -policy=dienes_ro -ttl=87600h
```

### Dienes

Copy the `conf.sample.yml` to `conf.yml` and edit accordingly.
The required changes are:

```yaml
vault:
  token: TOKEN_HERE
  host: https://vault.domain.tld:8200

api:
  cors:
    origins:
      - "http://localhost"
      - "https://localhost"
      - "http://localhost:8000"
      - "https://localhost:8000"
  allowed_hosts:
    - localhost
    - dienes.domain.tld
```

### Nginx

Generate SSL certificates for nginx
```bash
mkdir -pv /etc/nginx/ssl/certs /etc/nginx/ssl/keys
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/ssl/keys/nginx-selfsigned.key -out /etc/nginx/ssl/certs/nginx-selfsigned.crt
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096
```

Run the following command to disable the default site that comes with the nginx package
```bash
sed -i 's@ default_server@@' /etc/nginx/nginx.conf
```

Copy the preconfigured nginx vhost `dienes.conf`
```bash
yes | cp -v etc/nginx/dienes.conf /etc/nginx/conf.d/dienes.conf
```

Configure the vhost accordingly `/etc/nginx/conf.d/dienes.conf`
```conf
server_name dienes.domain.tld;  # change the server name
```

### Systemd

Copy the Systemd service files from `etc/systemd/` to `/etc/systemd/system/`
```bash
yes | cp -v etc/systemd/* /etc/systemd/system/
```

Copy the env files from `etc/default/` to `/etc/default/`
```bash
yes | cp -v etc/default/* /etc/default/
```

Finally, enable and run the services
```bash
systemctl daemon-reload
systemctl enable dienes.socket dienes dienes-worker dienes-beat nginx
systemctl restart dienes.socket dienes dienes-worker dienes-beat nginx
```

## Troubleshooting

Logs are located at `/var/log/dienes` and at `/var/log/nginx` and at system's journal.

```bash
journalctl -f -u dienes
journalctl -f -u dienes-beat
journalctl -f -u dienes-worker
```

## Testing

To run development servers, run the below commands on two different shells

> API server

```bash
uvicorn api:dienes --host 0.0.0.0 --port 10051
```

> Worker

```bash
celery -A worker worker -l info -B
```

> Python client (for benchmark)

Copy the client `client.sample.py` to `client.py` first and then edit the credentials inside the file.

```bash
python3 client.py
```

Optionally, the library `faker` can be used to test sample records

```python
from faker import Faker

faker = Faker()

dienes_url = 'http://localhost:8000/dns/record/ipv6/add'
for i in range(256):
    data = {
        'fqdn': '{name}.green.local'.format(name=get_random_string(8)),
        'ip': faker.ipv6(),
    }
    r = requests.post(dienes_url, auth=(dienes_username, dienes_password, ), json=data)
    print(r.json())
```

> Removing DNS server records with PowerShell

```powershell
$Zones = Get-DnsServerZone | Where-Object ZoneName -Like "*.local"
foreach ($Zone in $Zones) {
	$Records = Get-DnsServerResourceRecord -ZoneName $Zone.ZoneName
	foreach ($Record in $Records) {
		Remove-DnsServerResourceRecord -ZoneName $Zone.ZoneName -Type 1 -Name $Record.HostName
	}
}
```

> Removing DNS server zones with PowerShell

```powershell
$Zones = Get-DnsServerZone | Where-Object ZoneName -Like "*.ip6.arpa"
foreach ($Zone in $Zones) {
    Remove-DnsServerZone -Name $Zone.ZoneName -Force
}

$Zones = Get-DnsServerZone | Where-Object ZoneName -Like "*.in-addr.arpa"
foreach ($Zone in $Zones) {
    Remove-DnsServerZone -Name $Zone.ZoneName -Force
}
```
