#! /usr/bin/env python3
# Author: Sotirios Roussis <sroussis@space.gr>

"""
Redis schema CSV:
    Type,IP Version,Action,Record Type,IP Address,Fully Qualified Domain Name,TTL,Add PTR or not
    record,ipv4,add,a,172.20.14.2,dienes.domain.tld,01:00:00,true
"""

import os
import datetime
import secrets

import yaml
import hvac
import redis
import requests

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from urllib3.exceptions import InsecureRequestWarning

from libs.healthcheck.vault import vault_check
from libs.healthcheck.redis import redis_check, data_check
from libs.healthcheck.tcp import tcp_check
from libs.models.dns.record.add import *
from libs.models.dns.record.delete import *

NAME = 'Dienes Async API Server'
VERSION = '1.0.0'

# ignore self-signed certificate warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# read dienes configuration
with open(os.path.dirname(os.path.realpath(__file__)) + '/conf.yml', 'r') as f:
    conf = yaml.safe_load(f)

# initiate FastAPI server and plugins
security = HTTPBasic()
limiter = Limiter(key_func=get_remote_address)
dienes = FastAPI(title=NAME, version=VERSION)
dienes.add_middleware(GZipMiddleware, minimum_size=conf['api']['gzip']['minimum_size'])
dienes.add_middleware(CORSMiddleware, allow_origins=conf['api']['cors']['origins'],
                                      allow_credentials=conf['api']['cors']['credentials'],
                                      allow_methods=conf['api']['cors']['methods'])
dienes.add_middleware(TrustedHostMiddleware, allowed_hosts=conf['api']['allowed_hosts'])
dienes.state.limiter = limiter
dienes.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# initiate clients
redis_pool = redis.ConnectionPool(connection_class=redis.UnixDomainSocketConnection,
                                  path=conf['redis']['socket'],
                                  db=conf['redis']['database'])
r = redis.Redis(connection_pool=redis_pool, socket_connect_timeout=conf['redis']['connect_timeout'])
v = hvac.Client(url=conf['vault']['host'], token=conf['vault']['token'], verify=conf['vault']['ssl_verify'])


def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    try:
        _vault = v.secrets.kv.v2.read_secret_version(path=conf['vault']['paths']['api'] + '/' + credentials.username)
    except hvac.exceptions.InvalidPath:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Athenticate': 'Basic', },
        )

    if not secrets.compare_digest(credentials.password, _vault['data']['data']['password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Athenticate': 'Basic', },
        )
    
    return {
        'role': _vault['data']['data']['role'],
        'username': credentials.username,
    }

async def post_dns_record(user, name, response):
    if user['role'] != 'admin':
        response.status_code = status.HTTP_403_FORBIDDEN
        result = {
            'detail': 'Insufficient privileges',
        }

        return result

    if r.zscore(conf['redis']['key'], name):
        response.status_code = status.HTTP_406_NOT_ACCEPTABLE
        result = {
            'detail': 'The instruction "{name}" is already cached and not executed yet'.format(name=name),
        }

        return result

    r.zadd(conf['redis']['key'], {name: round(datetime.datetime.now().timestamp()), })
    result = {
        'detail': 'The instruction "{name}" has been queued up successfully'.format(name=name),
    }

    return result

@dienes.get('/', include_in_schema=False, status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def root(request: Request, response: Response):
    return {'detail': 'Serving beers 🍺', }

@dienes.get('/redoc', include_in_schema=False, status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def get_documentation_redoc(request: Request, user: dict = Depends(get_current_user)):
    return get_redoc_html(openapi_url='/openapi.json', title='docs')

@dienes.get('/docs', include_in_schema=False, status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def get_documentation_swagger(request: Request, user: dict = Depends(get_current_user)):
    return get_swagger_ui_html(openapi_url='/openapi.json', title='docs')

@dienes.get('/openapi.json', include_in_schema=False, status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def openapi(request: Request, user: dict = Depends(get_current_user)):
    return get_openapi(title=dienes.title, version=dienes.version, routes=dienes.routes)

@dienes.get('/health', status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def healthcheck(request: Request, response: Response, user: dict = Depends(get_current_user)):
    healthy = True
    results = {'detail': {}, }

    if 'redis' in conf['api']['healthcheck']['services']:
        healthcheck_redis = 1 if redis_check(r) else 0
        results['detail']['redis'] = [
            {
                'description': 'Redis health',
                'state': healthcheck_redis,
            },
        ]
        healthy = healthy if healthcheck_redis == 1 else False

        if 'data' in conf['api']['healthcheck']['services']:
            healthcheck_data = data_check(r, conf)
            results['detail']['data'] = [
                {
                    'description': 'Number of total pending instructions',
                    'state': healthcheck_data['pending'],
                },
                {
                    'description': 'Number of stale instructions',
                    'state': healthcheck_data['stale'],
                },
            ]

    if 'vault' in conf['api']['healthcheck']['services']:
        healthcheck_vault = 1 if vault_check(v) else 0
        results['detail']['vault'] = [
            {
                'description': 'Hashicorp Vault health',
                'state': healthcheck_vault,
            },
        ]
        healthy = healthy if healthcheck_vault == 1 else False

        _vault = v.secrets.kv.v2.read_secret_version(path=conf['vault']['paths']['dns'] + '/credentials')['data']['data']
        if 'winrm' in conf['api']['healthcheck']['services']:
            healthcheck_winrm = 1 if tcp_check(_vault['host'], _vault['winrm_port']) else 0
            results['detail']['winrm'] = [
                {
                    'description': 'WinRM over HTTP health (TCP connectivity)',
                    'state': healthcheck_winrm,
                },
            ]
            healthy = healthy if healthcheck_winrm == 1 else False
        
        if 'winrms' in conf['api']['healthcheck']['services']:
            healthcheck_winrms = 1 if tcp_check(_vault['host'], _vault['winrms_port']) else 0
            results['detail']['winrms'] = [
                {
                    'description': 'WinRM over HTTPS health (TCP connectivity)',
                    'state': healthcheck_winrms,
                },
            ]
            healthy = healthy if healthcheck_winrms == 1 else False

    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return results

@dienes.post('/dns/record/ipv4/add', status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def dns_record_ipv4_add(form: AddIPv4RecordModel, request: Request, response: Response, user: dict = Depends(get_current_user)):
    name = 'record,ipv4,add,a,{ip},{fqdn},{ttl},{ptr}'.format(ip=form.ip,
                                                              fqdn=form.fqdn,
                                                              ttl=form.ttl,
                                                              ptr=form.ptr)

    return await post_dns_record(user, name, response)

@dienes.post('/dns/record/ipv6/add', status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def dns_record_ipv6_add(form: AddIPv6RecordModel, request: Request, response: Response, user: dict = Depends(get_current_user)):
    name = 'record,ipv6,add,aaaa,{ip},{fqdn},{ttl},{ptr}'.format(ip=form.ip,
                                                                 fqdn=form.fqdn,
                                                                 ttl=form.ttl,
                                                                 ptr=form.ptr)

    return await post_dns_record(user, name, response)

@dienes.post('/dns/record/ipv4/delete', status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def dns_record_ipv4_delete(form: DeleteIPv4RecordModel, request: Request, response: Response, user: dict = Depends(get_current_user)):
    name = 'record,ipv4,delete,a,{ip},{fqdn},,'.format(ip=form.ip,
                                                       fqdn=form.fqdn)

    # return await post_dns_record(user, name, response)
    return {'detail': 'Not implemented yet', }

@dienes.post('/dns/record/ipv6/delete', status_code=status.HTTP_200_OK)
@limiter.limit(conf['api']['limit'])
async def dns_record_ipv6_delete(form: DeleteIPv6RecordModel, request: Request, response: Response, user: dict = Depends(get_current_user)):
    name = 'record,ipv4,delete,aaaa,{ip},{fqdn},,'.format(ip=form.ip,
                                                          fqdn=form.fqdn)

    # return await post_dns_record(user, name, response)
    return {'detail': 'Not implemented yet', }
