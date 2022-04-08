import os
import logging
import datetime

import hvac
import redis
import requests
import ipaddress

from jinja2 import Environment, FileSystemLoader
from pypsrp.client import Client
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
templates = os.path.dirname(os.path.realpath(__file__)) + '/../../templates'
template_map = {
    'record,ipv4,add,a': 'Add-DnsRecord-A.pwsh.j2',
    'record,ipv6,add,aaaa': 'Add-DnsRecord-AAAA.pwsh.j2',
    'record,ipv4,delete,a': 'Remove-DnsServerResourceRecord.pwsh.j2',
    'record,ipv6,delete,aaaa': 'Remove-DnsServerResourceRecord.pwsh.j2',
}

def execute(conf):
    r = redis.Redis(unix_socket_path=conf['redis']['socket'],
                    db=conf['redis']['database'],
                    socket_connect_timeout=conf['redis']['connect_timeout'])
    logging.debug('Connected to Redis "{socket}"'.format(socket=conf['redis']['socket']))

    # check counter if another task is already running and if yes, exit
    is_locked = r.get('celery:tasks_running:add_delete_records')
    is_locked = int(is_locked) if is_locked else 0
    if is_locked >= 1:
        logging.info('Task already running. Exiting.')
        r.close()
        logging.debug('Disconnected from Redis "{socket}"'.format(socket=conf['redis']['socket']))
        return None

    # increment counter in order to avoid duplicate tasks
    r.incr('celery:tasks_running:add_delete_records')
    logging.debug('Locked task')

    vault = hvac.Client(url=conf['vault']['host'], token=conf['vault']['token'], verify=conf['vault']['ssl_verify'])
    secrets = vault.secrets.kv.v2.read_secret_version(path=conf['vault']['paths']['dns'] + '/credentials')
    secrets = secrets['data']['data']

    with Client(secrets['host'], username=secrets['username'], password=secrets['password'],
                cert_validation=True if secrets['cert_validation'].lower() in ('true', 'on', 'yes', '1', ) else False) as c:
        results = r.zrangebyscore(conf['redis']['key'], 0, '+inf')
        for instruction in results[:conf['powershell']['tasks']['add_delete_records']['limit']]:
            instruction = instruction.decode()
            instructions = instruction.split(',')
            instruction_prefix = ','.join(instructions[:4])
            pwsh_script = template_map.get(instruction_prefix)
            if not pwsh_script:
                logging.warning('Cannot find appropriate PowerShell template to run for the instruction "{instruction}". Skipping.'.format(instruction=instruction))
                continue

            record_type = instructions[3]
            ip = instructions[4]
            fqdn = instructions[5].split('.')
            name = fqdn[0]
            zone = '.'.join(fqdn[1:])
            ttl = instructions[6]
            if instructions[7].lower() in ('true', 'ptr', 'yes', 'add', '1', 'on', ):
                ptr = '-CreatePTR'
                ptr_msg = 'with PTR'
                if record_type == 'a':
                    network_id = ipaddress.ip_network('{ip}{split_ipv4}'.format(ip=ip, split_ipv4=conf['dns']['zone']['split']['ipv4']), False).compressed
                elif record_type == 'aaaa':
                    network_id = ipaddress.ip_network('{ip}{split_ipv6}'.format(ip=ip, split_ipv6=conf['dns']['zone']['split']['ipv6']), False).compressed
            else:
                ptr = ''
                ptr_msg = 'without PTR'
                network_id = ''
            replication_scope = conf['dns']['zone']['replication_scope']

            file_loader = FileSystemLoader(templates)
            env = Environment(loader=file_loader)
            env.trim_blocks = True
            env.lstrip_blocks = True
            env.rstrip_blocks = True
            template = env.get_template(pwsh_script)

            cmd = template.render(ip=ip,
                                  name=name,
                                  zone=zone,
                                  ttl=ttl,
                                  ptr=ptr,
                                  ptr_msg=ptr_msg,
                                  network_id=network_id,
                                  replication_scope=replication_scope)
            output, streams, had_errors = c.execute_ps(cmd)

            for verbose in streams.verbose:
                logging.info(verbose)

            for error in streams.error:
                logging.error(error.exception)

            if len(streams.error) + len(streams.warning) == 0:
                r.zrem(conf['redis']['key'], instruction)
                logging.info('Removed member "{instruction}" from cache'.format(instruction=instruction))
            else:
                r.zadd(conf['redis']['key'], {instruction: round(datetime.datetime.now().timestamp()) * 2, })
                logging.warning('Updated score of member "{instruction}" because it failed to execute. Stale instruction'.format(instruction=instruction))

    # decrement counter in order to let other tasks to run
    r.decr('celery:tasks_running:add_delete_records')
    logging.debug('Unlocked task')

    r.close()
    logging.debug('Disconnected from Redis "{socket}"'.format(socket=conf['redis']['socket']))
    return None
