#! /usr/bin/env python3
# Author: Sotirios Roussis <sroussis@space.gr>

import os
import yaml

from celery import Celery

from libs.tasks.add_delete_records import execute as execute_add_delete_records


with open(os.path.dirname(os.path.realpath(__file__)) + '/conf.yml', 'r') as f:
    conf = yaml.safe_load(f)

worker = Celery('tasks', broker='redis+socket://{socket}'.format(socket=conf['redis']['socket']))
worker.conf.enable_utc = False

@worker.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(conf['powershell']['tasks']['add_delete_records']['interval'], add_delete_records.s(conf),
                             name='Run remote pwsh commands (if any available) every {interval} seconds'.format(interval=conf['powershell']['tasks']['add_delete_records']['interval']))

@worker.task(retry_backoff=5, max_retries=5, retry_jitter=True)
def add_delete_records(configuration):
    return execute_add_delete_records(configuration)
