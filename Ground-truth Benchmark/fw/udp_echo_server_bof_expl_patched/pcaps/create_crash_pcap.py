from scapy.all import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('UDP_Echo_Server_Client.s0i0.pcap')

def write(pkt):
    wrpcap('UDP_Echo_Server_Client_crash.pcap', pkt, append=True)  #appends packet to output file

# Let's iterate through every packet
for packet in packets:
    # We're only interested packets with a DNS Round Robin layer
    if packet.haslayer(UDP):
        #print(packet[UDP].payload)#b"Ciao"
        print("Before: ", len(packet[UDP]))
        packet[UDP].payload = conf.raw_layer(load=b"sending udp sending udp sending udp sending udp sending udp sending udp sending udp sending udp sending udp sending udp")
        #packet[UDP].length = len("sending udp sending udp sending udp sending udp sending udp sending udp sending udp sending udp sending udp sending udp")
        print("After: ", len(packet[UDP]))
    write(packet)