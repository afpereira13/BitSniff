import socket
from struct import *
from udp_parser import *
from ip_parser import  *
from tcp_parser import *

def parse_packet(packet) :

    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])

 #Parsing of IP packets
    if eth_protocol == 8:
        version, ihl, iph_length, ttl, protocol, s_addr, d_addr = parse_ip_packet(packet)
        if protocol == 6:
            print 'Destination MAC : ' + eth_macaddr(packet[0:6]) + ' Source MAC : ' + eth_macaddr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
            print 'TCP PACKET:'

            parse_tcp_packet(packet,iph_length)     #add s_addr and d_addr
        elif protocol == 17:
            print 'Destination MAC : ' + eth_macaddr(packet[0:6]) + ' Source MAC : ' + eth_macaddr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
            #PRINT
            print 'UDP PACKET:'
            #Log in file

            parse_udp_packet(packet,iph_length)     #add s_addr and d_addr
        else:
            print 'Protocol other than TCP/UDP'

        print

def eth_macaddr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
