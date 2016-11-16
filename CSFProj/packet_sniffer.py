import pcapy
import sys
from struct import *
from packet_parser import *

fo = open("sniffer.log", "w")
fo.write("LOG FILE:\n")
fo.close()

def main(argv):
    #list all devices
    devices = pcapy.findalldevs()
    print devices
    dev = devices[0]
    cap = pcapy.open_live(dev , 65536 , 1 , 0)
    couter = 0;
    while(True):
        (header, packet) = cap.next()
        print "Packet found"
        couter+=1
        print couter
        parse_packet(packet)


if __name__ == "__main__":
  main(sys.argv)