#this gives you the packet IP and their destination
from scapy.all import *
import matplotlib.pyplot as plt
# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('YTandpaper.pcap')
dict = {}
tuplist=[]
tupbyte=[]
numlist=[]
sortip=[]
# Let's iterate through every packet
for packet in packets:

    # only interested on  len(packets)the IP layer
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            ip = packet[IP]
            ipsource=ip.src

            ipdest=ip.dst
            length=len(ip.src)# how many bytes is the ip source
            tup = (ip.src,ip.dst)

            if tup in dict:
                dict[tup]+=length# add the length to the already ordered list
            else:
                dict[tup]=length  #make a new entry with the bytes
                tuplist.append(tup)

for ips in tuplist:
    tupbyte.append(dict[ips])#makes a list of the bytes for the graph

#print(tuplist)
tuplist = [a + " " + b for (a,b) in tuplist]
#this says for (a,b) in tuplist so pairs it says concatinate a and b with a space
#print(dict)
tupbyte.sort()
#print(tupbyte)
lengthofbytes=len(tupbyte)
for i in range(lengthofbytes):
    for key in dict:
        #print("the number of i is ",i,"and the tupbyte[i] is ",tupbyte[i],"and key is ",key, "and the ports are  is ",ip.sport,"  ",ip.dport)
        if dict[key]==9212:
            print("These are the keys",key,"the ports are ",ip.sport,"  ",ip.dport)
        if(tupbyte[i]==dict[key]):

            sortip.append(str(key))

            break
    del dict[key]

print(sortip)
print(tupbyte)

plt.xlabel("IP connections")
plt.ylabel("# of Bytes")
plt.bar(sortip, tupbyte)
plt.yscale('log')
plt.xticks(sortip,sortip, rotation='vertical')
plt.show()
