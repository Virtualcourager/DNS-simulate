import socket
import queue
import struct
import threading
import getopt
import sys
import random
import init as ini
import tool as to
dns_data = {}  
dns_server = '10.3.9.5' 
port = 53  
query_buffer = queue.Queue() 
answer_buffer = queue.Queue()  
txt_name = 'dnsrelay.txt'  
id_store = {}  
def create_dns_server():
    global dns_server, port, answer_buffer, query_buffer, dns_data
    print('Creating local DNS server...(UDP)')
    print('Remote DNS server: [%s]' % dns_server)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        print('Binding socket [%s:%s]...' % ('127.0.0.1', port))
        s.settimeout(1)
        s.bind(('', port)) 
        while True:
            try:
                while not answer_buffer.empty():
                    ans, src_addr = answer_buffer.get()
                    s.sendto(ans, src_addr)
                data, addr = s.recvfrom(1024)
                flags = data[2:4]
                type = data[-4:-2]
                if flags == b'\x01\x00' and type == b'\x00\x01':
                    print('[DNS QUERY FROM]', addr)
                    q_name = get_qname(data)
                    print('[Q_NAME]', q_name)
                    ans_ip = to.look_up(q_name,dns_data)

                    if ans_ip == '0.0.0.0':
                        ans = create_ans_frame(data, ans_ip, banned=True)
                        s.sendto(ans, addr)
                        print('[NOTE] Domain does not exist.')

                    elif len(ans_ip) > 0:
                        print('Domain [%s] \'s IP has been found, is [%s]' % (q_name, ans_ip))
                        ans = create_ans_frame(data, ans_ip, banned=False)
                        s.sendto(ans, addr)
                        print('[CREATED RESPONSE]', ans)

                    else:
                        print('IP not found. Sending query to [%s]' % dns_server)
                        query_buffer.put((data, addr))

            except:
                pass

def send_dns_frame(server, frm, addr):
    global dns_server, port, id_store
    id = struct.unpack('!H', frm[0:2])

    if id[0] in id_store:
        new_id = (2 * id[0] + random.randint(0, 65535)) % 65536
        frm = struct.pack('!H', new_id) + frm[2::]
        id_store[new_id] = (id[0], addr)

    else:
        id_store[id[0]] = (id[0], addr)
    print('[SEND QUERY]', get_qname(frm))
    server.sendto(frm, (dns_server, port))

def get_qname(dns_frm):
    segs = []
    q_name_bytes = dns_frm[12:-2]  
    i = 0
    cnt = q_name_bytes[0]
    while cnt != 0:
        segs.append(q_name_bytes[i + 1:i + cnt + 1].decode('ascii'))
        i += cnt + 1
        cnt = q_name_bytes[i]

    return '.'.join(segs)

def create_ans_frame(dns_frm, ans_ip, banned):

    id = dns_frm[0:2] 
    q_count = b'\x00\x01' 
    if not banned:
        flags = b'\x81\x80' 
        ans_RRs = b'\x00\x01'  
    else:
        flags = b'\x81\x83' 
        ans_RRs = b'\x00\x00' 
    auth_RRs = b'\x00\x00' 
    add_RRs = b'\x00\x00'  
    header = id + flags + q_count + ans_RRs + auth_RRs + add_RRs
    queries = dns_frm[12::]  
     
    name = b'\xc0\x0c'  
    type = b'\x00\x01' 
    a_class = b'\x00\x01'  
    ttl = struct.pack('!L', 46) 
    data_length = struct.pack('!H', 4)  
    ip_num = ans_ip.split('.')
    address = struct.pack('!BBBB', int(ip_num[0]), int(ip_num[1]), int(ip_num[2]), int(ip_num[3]))
    answers = name + type + a_class + ttl + data_length + address
    return header + queries + answers


def handle_dns_ans():
    global id_store, query_buffer, answer_buffer
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', 50000))
        s.settimeout(1)
        while True:
            try:
                while not query_buffer.empty():
                    frm, addr = query_buffer.get()
                    send_dns_frame(s, frm, addr)
                data, addr = s.recvfrom(1024)
                print('[RESPONSE]', to.get_ip(data))

                id = struct.unpack('!H', data[0:2])
                src_id, src_addr = id_store[id[0]]
                data = struct.pack('!H', src_id) + data[2::]

                answer_buffer.put((data, src_addr))

                id_store.pop(id[0])

            except:
                pass
if __name__ == '__main__':
    ini.init_host_file(txt_name, dns_data)
    handle_query = threading.Thread(target=create_dns_server, args=(), name='role_server').start()
    handle_ans = threading.Thread(target=handle_dns_ans, args=(), name='role_client').start()
