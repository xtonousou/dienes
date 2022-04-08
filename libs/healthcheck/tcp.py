import socket

def tcp_check(dst, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((dst, int(port), ))
        s.close()
    except Exception:
        return False

    return True
