from struct import *

def parse_tcp_packet(packet,iph_length) :
    eth_length = 14
    t = iph_length + eth_length
    tcp_header = packet[t:t+20]

    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    ack = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    print 'Protocol : TCP |' + 'Source Port : ' + str(source_port) + '|' + ' Dest Port : ' + str(dest_port) + '|' + ' Sequence Number : ' + str(sequence) + '|' + ' Acknowledgement : ' + str(ack) + '|' + ' TCP header length : ' + str(tcph_length)
    logdata= 'Packet|' + 'Protocol:TCP|' + 'Source Port:' + str(source_port) + '|' + 'Dest Port:' + str(dest_port) + '|' + 'Sequence Number:' + str(sequence) + '|' + 'Acknowledgement:' + str(ack) + '|' + 'TCP header length:' + str(tcph_length)


    h_size = eth_length + iph_length + tcph_length * 4
    data_size = len(packet) - h_size
    data = packet[h_size:]

    fo = open("sniffer.log", "a")
    fo.write(logdata + ":\n" + 'Data|' + data + "\n")
    fo.close()
    #print 'Data : ' + data