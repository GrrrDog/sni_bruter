import socket
import argparse
import M2Crypto
import re

print 'titko v0.1'
print 'TLS SNI vhosts bruteforcer PoC'
print 
print 'Alexey Tyurin - agrrrdog at gmail.com'
print 'Digital Security Research Group - http://www.dsecrg.ru'
parser = argparse.ArgumentParser()
parser.add_argument('-t', action='store', dest='hostname', required=True, help='Set a target\'s hostname or IP address')
parser.add_argument('-p', action='store', dest='port', default='443', type=int, help='Set a target\'s port')
parser.add_argument('-w', action='store', dest='word_list', default='hostnames.txt', help='Set a list of hostnames for the bruteforce')
parser.add_argument('-v', action='store', dest='verbose', default=False, help='Be more verbose and show plain replies (ugly, for debug)')

args = parser.parse_args()


def send_sni(hostname, port, sni_name):
    BUFFER_SIZE = 8196
    sni_name_len=len(sni_name)
    full_len=0x88+sni_name_len
    #print full_len
    #print hex(full_len)
    hello_len=0x84+sni_name_len
    #print hello_len
    #print hex(hello_len)
    ext_len=0x31+sni_name_len
    #print ext_len
    #print hex(ext_len)
    MESSAGE= """\x16\x03\x01\x00"""+chr(full_len)+"""\x01\x00\x00""" +chr(hello_len)+"""\x03\x01\x9d\xf3\xb6\x6c\x53\x75\xb3\x99\xd3\x3a\x07\x41\xa0\xa0\xa0\xb4\xc6\x78\x16\x8e\xe0\x30\x02\xda\x68\xc8\xef\x96\x1b\x68\xc0\x29\x00\x00\x2a\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\xc0\x12\xc0\x07\xc0\x11\x00\x33\x00\x32\x00\x45\x00\x39\x00\x38\x00\x88\x00\x16\x00\x2f\x00\x41\x00\x35\x00\x84\x00\x0a\x00\x05\x00\x04\x01\x00\x00"""+chr(ext_len)+"""\x00\x00\x00"""+chr(sni_name_len+5)+"""\x00"""+chr(sni_name_len+3)+"""\x00\x00"""+chr(sni_name_len)+sni_name+"""\xff\x01\x00\x01\x00\x00\x0a\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x33\x74\x00\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00"""
    #MESSAGE="""\x16\x03\x01\x00\x93\x01\x00\x00\x8f\x03\x01\x9d\xf3\xb6\x6c\x53\x75\xb3\x99\xd3\x3a\x07\x41\xa0\xa0\xa0\xb4\xc6\x78\x16\x8e\xe0\x30\x02\xda\x68\xc8\xef\x96\x1b\x68\xc0\x29\x00\x00\x2a\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\xc0\x12\xc0\x07\xc0\x11\x00\x33\x00\x32\x00\x45\x00\x39\x00\x38\x00\x88\x00\x16\x00\x2f\x00\x41\x00\x35\x00\x84\x00\x0a\x00\x05\x00\x04\x01\x00\x00\x3c\x00\x00\x00\x10\x00\x0e\x00\x00\x0b\x62\x72\x72\x72\x2e\x6f\x72\x67\x2e\x72\x75\xff\x01\x00\x01\x00\x00\x0a\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x33\x74\x00\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00"""
    #print MESSAGE
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((hostname, port))
    except Exception, e:
        print 'Something is wrong with %s:%d. Exception type is %s' % (hostname, port, `e`)
        exit()
    s.send(MESSAGE)
    data = s.recv(BUFFER_SIZE)
    s.close()
    return data

def parse_cert(data):
    hex_data=data.encode('hex')
    certs_chain_re=re.search( r'160301....0b.*', hex_data)
    certs_chain_data= certs_chain_re.group() 
    certs_chain_data= certs_chain_data.decode('hex')
    if( data.find('\x15\x03\x01')==0):
        print "SSL Alert - Unrecognized Name"  # 2nd packet with certs
    cert_start_packet=0 # 2nd packet with certs
    #print cert_start_packet
    cert_chain_start=cert_start_packet+3+2+1+3 #2nd tls header+total length+handshake type+length
    
    #Base for parsing of cert chains
    cert_chain_length_hex=certs_chain_data[cert_chain_start:cert_chain_start+3]
    cert_chain_length= int(cert_chain_length_hex.encode('hex'), 16)
    cert_chain=certs_chain_data[cert_chain_start+3:cert_chain_start+3+cert_chain_length]
    #print cert_chain.encode('hex')
    
    cert_length=int(cert_chain[0:3].encode('hex'), 16)
    #print cert_length
    cert_der=cert_chain[3:cert_length+3]
    # print cert_der
    
    x509 = M2Crypto.X509.load_cert_der_string(cert_der)
    subj= x509.get_subject().as_text()
    return subj

with open(args.word_list) as f:
    try:
        names = f.readlines()
    except : 
        print "Coudn't find the file with hostnames - ", args.word_list
        exit()

names = map(lambda s: s.strip(), names)

print
print "Starting..."
print "Target: %s:%s" % (args.hostname, args.port)
print 
for cur_name in names:
    print "Trying %s " % cur_name.rstrip()
    reply=send_sni (args.hostname, args.port, cur_name)
    if args.verbose:
        print "received data:", reply
    print "The SSL reply length: ", len(reply)
    subj= parse_cert(reply)
    print "Subject field from the certificate : %s " %  subj
    print
print "Finished" 

