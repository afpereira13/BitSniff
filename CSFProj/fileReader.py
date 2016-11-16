__author__ = 'jorgemartins'
from portSniffer import *

def barException(c,i):
    result=""
    while i < len(c):
        if c[i] == '':
            if i != len(c)-1:
                result+= '|'
            else:
                result+=''
        elif (i == len(c)-1) & (c[i] != ''):
             result+= c[i]
        else:
            result+= c[i] + '|'
        i+=1
    return result


data=""
packet={}
listOfTcp= []
listOfUdp= []
isData=False

with open('sniffer.log') as f:
    for line in f:
        if line == 'LOG FILE:\n':           #salta a primeira linha do ficheiro
            continue
        if '|' in line:                     #se contiver '|' significa que pode ser data ou packet
            c= line.split('|')
            if c[0] == 'Data':              #se for data cria variavel para adicionar data
                isData=True

                if len(c) <= 1:
                    data+= c[1]
                    if 'Data' not in packet.keys():
                       packet['Data'] = data
                else:
                    result= barException(c,1)
                    if 'Data' not in packet.keys():
                       packet['Data'] = result
                    else:
                        packet['Data']+= result
            elif c[0] == 'Packet':          #se for packet faz split pelo '|' e adiciona os campos ao dicionario
                print str(isData) + "when in packet"
                if isData == True:
                    isData= False
                    if packet['Protocol'] == 'TCP':
                        listOfTcp.append(packet)
                    else:
                        listOfUdp.append(packet)
                    print 'added'
                    packet={}
                data=""
                i=1
                while i < len(c):
                    packetInfo= c[i].split(':')
                    packet[packetInfo[0]] = packetInfo[1]
                    i+=1
            else:                           #se na data existir o caracter '|'
                result= barException(c,0)
                packet['Data']+= result

        else:                               #caso nao seja nem data nem packet quer dizer que e a data restante
            packet['Data']+= line

if packet['Protocol'] == 'TCP':
    listOfTcp.append(packet)
else:
    listOfUdp.append(packet)
print packet

print listOfTcp
print listOfUdp
port_Sniffer(listOfUdp)









