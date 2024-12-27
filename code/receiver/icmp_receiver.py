from scapy.all import sniff, IP, ICMP
# Define a callback function to process received packets
def handle_packet(packet):
    # Check if the packet is an ICMP packet with TTL=1
    if IP in packet and ICMP in packet and packet[IP].ttl == 1:
        packet.show()
#sniff(filter="icmp", prn=handle_packet)
