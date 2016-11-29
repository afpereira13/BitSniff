import sys


def makeFile(path_read,path_write):
    parse_file = open(path_write,"w+")
    string_count=1
    string_aux=""
    count_no_packet=0
    try:
        with open(path_read,"r") as f:
            while(1):
                line=f.readline()
                if "MY" in line:
                    parse_file.write(line)
                elif string_count>0:
                    string_aux+=line
                    if line in ["", "\n"]:
                        parse_file.write(string_aux)
                        string_aux=""
                        count_no_packet+=1
                        if count_no_packet==3:
                            break
                    else:
                        count_no_packet=0
                if count_no_packet==3:
                    break
                string_count+=1
    except:
        print "Unexpected error:", sys.exc_info()[0]


def makeDict(list_aux):
    dict_aux={}
    key=""
    value=""
    for member in list_aux:
        for arg in member:
            if key=="":
                key=arg
            elif value=="":
                dict_aux[key]=arg
                key=""
    return dict_aux

### Web ports (80, 443, 8080, etc.) are not among packets desire
def heuristic0(all_packets):
    packets = []
    for packet in all_packets:
        if packet["Source_Port:"] not in ["80", "443", "8080"] and packet["Dest_Port:"] not in ["80", "443", "8080"]:
            packets.append(packet)
    return packets
    
def heuristic1(outcoming_packets, incoming_packets, myIP):
    return True
    
def heuristic2(outcoming_packets, incoming_packets, myIP):
    return True
    
def heuristic3(outcoming_packets, incoming_packets, myIP):
    return True
    
    
### those identical flows are from P2P applications if at least 
### two of each are found
### flow identities (source_IP, dest_IP, source_port, dest_port, 
###                                              prot_byte, TOS) 
### exist in relatively short measurements.     
def heuristic4(outcoming_packets, incoming_packets, myIP):
    return True
    
### if an IP uses a TCP/UDP port more than 5 times in the measurement
### period that {IP,port} pair indicates P2P traffic. The selected
### upper threshold (5) is a rule of thumb established empirically    
def heuristic5(outcoming_packets, incoming_packets, myIP):
    return True

def h6Aux(IO_packets, IOFlag):
    flow={}
    have=0
    IOflows=[]
    for packet in IO_packets:
        if len(IOflows)>0:
            for item in IOflows:
                if IOFlag=="I":
                     if item["Source_Address"] == packet["Source_Address:"]:
                        item["end_time"]=packet["Time:"]
                        item["Bytes"]+=int(packet["Data Size"][:-1])
                        item["# packets"]+=1
                        have=1
                        break
                elif IOFlag=="O":
                    if item["Destination_Address"] == packet["Destination_Address:"]:
                        item["end_time"]=packet["Time:"]
                        item["Bytes"]+=int(packet["Data Size"][:-1])
                        item["# packets"]+=1
                        have=1
                        break
                else:
                    have=0
        if have==0:
            if IOFlag=="I":
                flow["Source_Address"]=packet["Source_Address:"]
            else:
                flow["Destination_Address"]=packet["Destination_Address:"]
            flow["Bytes"]=int(packet["Data Size"][:-1])
            flow["init_time"]=packet["Time:"]
            flow["end_time"]=packet["Time:"]
            flow["# packets"]=1
            IOflows.append(flow)
            flow={}
    return IOflows
    
### flows are considered P2P flows which have flow size larger than 
### 1 MB or flow length is longer than 10 minutes
def heuristic6(outcoming_packets, incoming_packets, IP):
    torrent_exist=0
    
    flows_incoming=[]
    flows_outcoming=[]
    
    flows_outcoming=h6Aux(outcoming_packets,"O")
    flows_incoming=h6Aux(incoming_packets,"I")

    for packet in flows_outcoming:
        time_up=float(packet["end_time"][:-1])-float(packet["init_time"][:-1])
        if packet["Bytes"]>=1000000 or (packet["# packets"]>(int(time_up/10)) and time_up> 600.00):
            torrent_exist+=1
            print "BitTorrent flow from",IP[:-1],"to",packet["Destination_Address"]
    for packet in flows_incoming:
        time_up=float(packet["end_time"][:-1])-float(packet["init_time"][:-1])
        if packet["Bytes"]>=1000000 or (packet["# packets"]>(int(time_up/10)) and time_up> 600.00):
            torrent_exist+=1
            print "BitTorrent flow from",packet["Source_Address"],"to",IP[:-1]
    print "# Flows=",torrent_exist
    return True

    
    
    
def myIP(packet):
    return packet["MY IP"]
    
def incoming(packets,IP):
    incoming_packets=[]
    for packet in packets[1:]:
        if packet["Destination_Address:"] == IP:
            incoming_packets.append(packet)    
    return incoming_packets
    
def outcoming(packets,IP):    
    outcoming_packets=[]
    for packet in packets[1:]:
        if packet["Source_Address:"] == IP:
            outcoming_packets.append(packet)
    return outcoming_packets        
### return the packets which we can  consider bittorrent packets
### by heuristic

### TO DO:
    ###remove duplicated packets (Return)
def heuristics(packets, IP, totalPackets, totalNotWebPackets):
    outcoming_packets=outcoming(packets,IP)
    incoming_packets=incoming(packets,IP)
    if heuristic1(outcoming_packets, incoming_packets, IP) == True:
        if heuristic2(outcoming_packets, incoming_packets, IP) == True:
            if heuristic3(outcoming_packets, incoming_packets, IP) == True:
                if heuristic4(outcoming_packets, incoming_packets, IP) == True:
                    if heuristic5(outcoming_packets, incoming_packets, IP) == True:
                        if heuristic6(outcoming_packets, incoming_packets, IP) == True:
                            print "Exist BitTorrent traffic"
                            return True
    return False
    
def makeStruct(path_read):
    try:
        with open(path_read,"r") as f:
            listOfPackets=[]
            list_aux=[]
            count_no_packet=0
            while(1):
                line=f.readline()
                if not line in ['\n','']:
                    count_no_packet=0
                    if "MY IP" in line or "Data" in line:
                        list_aux.append(line.split(": "))
                    else:
                        list_aux.append(line.split(" "))
                else:
                    packet_on_dict = makeDict(list_aux)
                    if bool(packet_on_dict):
                        listOfPackets.append(makeDict(list_aux))
                    list_aux=[]
                    count_no_packet+=1
                    if count_no_packet==3:
                        break
            return listOfPackets
    except:
        print "Unexpected error:", sys.exc_info()[0]
    
    
#makeFile("cap.bs","bit.bs")
all_packets = makeStruct("cap.bs")
totalPackets = len(all_packets)-1 #number of packets captured
IP=myIP(all_packets[0])
packets = heuristic0(all_packets[1:])
totalNotWebPackets = len(packets) #number of packets captured w/out web ports
heuristics(packets,IP, totalPackets, totalNotWebPackets)
print "% of not WEB packets",totalNotWebPackets*1.0/totalPackets*100.0
