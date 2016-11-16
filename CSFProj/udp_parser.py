from struct import *

def parse_udp_packet(packet,iph_length) :
    eth_length = 14
    u = iph_length + eth_length
    udph_length = 8
    udp_header = packet[u:u+8]

    udph = unpack('!HHHH' , udp_header)

    source_port = udph[0]
    dest_port = udph[1]
    length = udph[2]
    checksum = udph[3]


    print 'Protocol : UDP ' + 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
    logdata = 'Packet|' + 'Protocol:UDP|'+ 'Source Port:' + str(source_port) + '|' + 'Dest Port:' + str(dest_port) + '|' + 'Length:' + str(length) + '|' + 'Checksum:' + str(checksum)

    h_size = eth_length + iph_length + udph_length
    data_size = len(packet) - h_size

    data = packet[h_size:]

    fo = open("sniffer.log", "a")
    fo.write(logdata + ":\n" + 'Data|' + data + "\n")
    fo.close()
    #print 'Data : ' + data