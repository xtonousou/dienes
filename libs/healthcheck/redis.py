import datetime

def redis_check(client):
    try:
        return client.ping()
    except Exception:
        return False

def data_check(client, conf):
    now = round(datetime.datetime.now().timestamp())

    stale_members = client.zrangebyscore(conf['redis']['key'], now + 1337, '+inf', withscores=False)
    all_members = client.zrangebyscore(conf['redis']['key'], 0, '+inf', withscores=False)

    return {
        'stale': len(stale_members),
        'pending': len(all_members),
    }
