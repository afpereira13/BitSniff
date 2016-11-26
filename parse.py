import sys


def makeFile(path_read,path_write):
    parse_file = open(path_write,"w+")
    string_aux=""
    try:
        with open(path_read,"r") as f:
            for line in f:
                if line in ['\n',' ']:
                    string_aux=""
                else:
                    string_aux+=line
                    if "Data" in line:
                        string_aux+="\n"
                        if "UDP" in string_aux or "TCP" in string_aux:
                            parse_file.write(string_aux)
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

    
def makeStruct(path_read):
    try:
        with open(path_read,"r") as f:
            dict_packet={}
            listOfPackets=[]
            string_aux=""
            list_aux=[]
            for line in f:
                if not line in ['\n',' ']:
                    string_aux=line
                    if "Data" in line:
                        list_aux.append(string_aux.split(": "))
                        if "UDP" in list_aux[0][1] or "TCP" in list_aux[0][1]:
                            dict_packet = makeDict(list_aux)
                            listOfPackets.append(dict_packet)
                    else:
                        list_aux.append(string_aux.split(" "))
            print listOfPackets
    except:
        print "Unexpected error:", sys.exc_info()[0]
    
    
makeFile("cap.bs","bit.bs")
makeStruct("cap.bs")
