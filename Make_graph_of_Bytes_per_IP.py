#gives a graph for bytes per IP
from scapy.all import *
import matplotlib.pyplot as plt

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('server-tcpdump-reno-10bw-40rtt-4096q-20180627T104452.pcap')
dict = {}
dictlist=[]
byteslist=[]
sortip=[]
# Let's iterate through every packet and see if their IP is in dict and if if it is add the number of bytes or initialize another entry to the dict and add the length
for packet in packets:
    # only interested on  len(packets)the IP layer
    if packet.haslayer(IP):
        ip = packet[IP]
        ipNum=ip.src
        ipNum=str(ipNum)# to have a string of IP #
        length=len(packet)# to find the length of the packet
        #print(ipNum)

        if ipNum in dict:
            adding = dict.get(ipNum) # adding equals all the bytes in previous packets with the same IP
            dict[ipNum]=adding+length# add that to the length of this packet

        else:
            dict[ipNum]=length#the bytes on this packet are the new value in the dictionary for this IP address
            dictlist.append(ipNum)#list for the graph

#for every IP in the dictlist get the value(Bytes) and append it to a list
for ips in dictlist:
    byteslist.append(dict[ips])
print(dictlist)


byteslist.sort()

#because Im sorting the bytes for the graph I have to make sure that the IPs of each change with their corresponding one
for i in range(len(byteslist)):
    for key in dict:# for every entry in the dictionary

        if(byteslist[i]==dict[key]): #if the number of bytes matches the value that the dictionary append it to this sortip so the bytes and ip match

            sortip.append(str(key))
            break
    del dict[key]# after the break we are gonna delete that entry so if something else has the same bytes its not gonna put that already use IP


plt.xlabel("IP address")
plt.ylabel("# of Bytes")
plt.bar(sortip,byteslist)
plt.yscale('log')
plt.xticks(sortip, sortip, rotation='vertical')
plt.show()
