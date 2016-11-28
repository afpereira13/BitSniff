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

    
def heuristic1(packets):
    return packets
    
def heuristic2(packets):
    return packets
    
def heuristic3(packets):
    return packets
    
def heuristic4(packets):
    return packets
    
def heuristic5(packets):
    return packets

def heuristic6(packets):
    return packets

### return the packets which we can  consider bittorrent packets
### by heuristic

### TO DO:
    ###remove duplicated packets (Return)
def heuristics(packets):
    bit_packets=[]
    bit_packets.append([heuristic1(packets)])
    bit_packets.append([heuristic2(packets)])
    bit_packets.append([heuristic3(packets)])
    bit_packets.append([heuristic4(packets)])
    bit_packets.append([heuristic5(packets)])
    bit_packets.append([heuristic6(packets)])
    return bit_packets
    
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
                    list_aux.append(line.split(": "))
                else:
                    packet_on_dict = makeDict(list_aux)
                    if bool(packet_on_dict):
                        listOfPackets.append(makeDict(list_aux))
                    list_aux=[]
                    count_no_packet+=1
                    if count_no_packet==3:
                        break
            print len(listOfPackets), listOfPackets[-1]
            return listOfPackets
    except:
        print "Unexpected error:", sys.exc_info()[0]
    
    
#makeFile("cap.bs","bit.bs")
packets = makeStruct("cap.bs")
heuristics(packets)