from ping3 import ping

def is_alive(host: str):
    response = ping(host)
    return response is not None