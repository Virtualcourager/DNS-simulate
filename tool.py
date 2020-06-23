import socket
import random
import queue
import getopt
import sys
import threading
import struct
def get_ip(dns_frame):
    ip1, ip2, ip3, ip4 = struct.unpack('!BBBB', dns_frame[-4::])
    return str(ip1) + '.' + str(ip2) + '.' + str(ip3) + '.' + str(ip4)

def look_up(q_name,dns_data):
    if q_name not in dns_data:
        return ''
    else:
        return dns_data[q_name]
