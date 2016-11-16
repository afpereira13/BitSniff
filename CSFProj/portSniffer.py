__author__ = 'jorgemartins'
import scapy

def port_Sniffer(listOfPackets):
    listOfBitPorts=[]
    for packet in listOfPackets:
        print packet['Source Port']
        if ((packet['Source Port'] >= 6881) & (packet['Source Port'] <= 6889)) | ((packet['Dest Port'] >= 6881) & (packet['Dest Port'] <= 6889)):
           listOfBitPorts.append(packet)
        if '' in packet['Data']:
            listOfBitPorts.append(packet)
    return  listOfBitPorts