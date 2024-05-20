def dec_to_ip(_dec):
    ip = ''
    for i in range(4):
        ip1 = ''
        for j in range(8):
            ip1=str(_dec % 2)+ip1
            _dec = _dec >> 1
        ip = ip + '.' + str(int(ip1, 2))
    return ip.strip('.')

def format_mac_ip(_hex):
    _mac_ip = ''
    for x in range(0, 12, 2):
        _mac_ip += str(_hex[x:x+2].decode('UTF-8')) + ':'
    return _mac_ip[:-1]
