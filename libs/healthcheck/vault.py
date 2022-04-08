def vault_check(client):
    try:
        vault_status = client.sys.read_health_status(method='GET')
        if isinstance(vault_status, dict):
            if vault_status.get('initialized') is False or vault_status.get('sealed') is True:
                return False
            return True
        return False
    except Exception:
        return False
