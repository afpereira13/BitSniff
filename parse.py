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

    
### flows are considered P2P flows which have flow size larger than 
### 1 MB or flow length is longer than 10 minutes
def heuristic6(outcoming_packets, incoming_packets, myIP):
    
    return True

def myIP(packets):
    return packets[0]["MY IP"]
    
def incoming(packets,myIP):
    incoming_packets=[]
    for packet in packets[1:]:
        if packet["Destination_Address:"] == myIP:
            incoming_packets.append(packet)    
    return incoming_packets
    
def outcoming(packets,myIP):    
    outcoming_packets=[]
    for packet in packets[1:]:
        if packet["Source_Address:"] == myIP:
            outcoming_packets.append(packet)
    return outcoming_packets        
### return the packets which we can  consider bittorrent packets
### by heuristic

### TO DO:
    ###remove duplicated packets (Return)
def heuristics(packets):
    IP=myIP(packets)
    outcoming_packets=outcoming(packets,IP)
    incoming_packets=incoming(packets,IP)
    if heuristic1(outcoming_packets, incoming_packets, myIP) == True:
        if heuristic2(outcoming_packets, incoming_packets, myIP) == True:
            if heuristic3(outcoming_packets, incoming_packets, myIP) == True:
                if heuristic4(outcoming_packets, incoming_packets, myIP) == True:
                    if heuristic5(outcoming_packets, incoming_packets, myIP) == True:
                        if heuristic6(outcoming_packets, incoming_packets, myIP) == True:
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
                    if "MY IP" in line:
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
    
    
makeFile("cap.bs","bit.bs")
packets = makeStruct("cap.bs")
heuristics(packets)
