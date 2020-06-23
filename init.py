import sys
def init_host_file(txt_name, dns_data):
    try:
        with open(txt_name, 'r') as f:
            for line in f.readlines():
                line = line.replace('\n', '')
                if len(line) > 0:
                    ip = line.split(' ')[0]
                    name = line.split(' ')[1]
                    dns_data[name] = ip
        print('Successfully Init data files .')
        print('Data Storage: ', len(dns_data))
    except:
        print('UNsuccessfully Init data files')
