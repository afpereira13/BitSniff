#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
 
import socket, sys
from struct import *
 
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print """Socket could not be created. 
    Error Code: {}
    Message: {}""".format(str(msg[0]),msg[1])
    
    sys.exit()
cap_file=open("cap.bs","w+")
# receive a packet
while True:
    packet = s.recvfrom(65565)
     
    #packet string from tuple
    packet = packet[0]
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
         
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        
        proto = str(protocol)
        
        if protocol == 6:
            proto="TCP"
        elif protocol == 17:
            proto="UDP"
 
        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
 
            #now unpack them :)

	    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
	    source_port = tcph[0]
	    dest_port = tcph[1]
	    sequence = tcph[2]
	    acknowledgement = tcph[3]
	    doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
	    if (dest_port==51413 or source_port==51413):
		try:    
			h_size = eth_length + iph_length + tcph_length * 4
            		data_size = len(packet) - h_size
             
            		#get data from the packet
            		data = (packet[h_size:])
           	    	aux=""
			aux+= "Protocol:"+ proto+ 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port)# + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length) + "\n"
			aux+= 'Source MAC: '+eth_addr(packet[6:12]) + "\n"
			aux+= 'Destination MAC:'+eth_addr(packet[0:6]) + "\n"
			#aux+= "Version:" + str(version) + "\n"
			#aux+= "IP Header Length:"+ str(ihl) + "\n"
			#aux+= "TTL:"+ str(ttl) + "\n"
			aux+= "Source Address:"+ str(s_addr) + "\n"
			aux+= "Destination Address:"+str(d_addr) + "\n"
			aux+= 'Data : ' + data + "\n\n"
			cap_file.write(aux)
		except:
		    print "Unexpected error:", sys.exc_info()[0]
            #print tcp.getTCP(tcp_header)
            
            	
        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #now unpack them
            #print udp.getUDP(udph_length, udp_header)
	    udph = unpack('!HHHH' , udp_header)
     
    	    source_port = udph[0]
	    dest_port = udph[1]
	    length = udph[2]
	    checksum = udph[3]

	    if (dest_port==51413 or source_port==51413):
		try:
			h_size = eth_length + iph_length + udph_length
		        data_size = len(packet) - h_size
		     
		    	#get data from the packet
		    	data = (packet[h_size:])
		     
			aux=""
		    	aux+= "Protocol: "+ proto+ ' Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port)# + ' Length : '+str(length)+' Checksum : '+str(checksum) +"\n"
			aux+= 'Source MAC: '+eth_addr(packet[6:12]) + "\n"
			aux+= 'Destination MAC:'+eth_addr(packet[0:6]) + "\n"
			#aux+= "Version:" + str(version) + "\n"
			#aux+= "IP Header Length:"+ str(ihl) + "\n"
			#aux+= "TTL:"+ str(ttl) + "\n"
			aux+= "Source Address:"+ str(s_addr) + "\n"
			aux+= "Destination Address:"+str(d_addr) + "\n"
			aux+= 'Data : ' + data + "\n\n"
			cap_file.write(aux)
		except:
		    print "Unexpected error:", sys.exc_info()[0]
		    
           
 
        #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP'
        print "-------------NADA--------------"
