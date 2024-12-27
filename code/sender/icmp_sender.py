from scapy.all import IP, ICMP, send
# Define the target IP address (replace with the receiver container's IP)
target_ip = "172.18.0.3"
# Create an ICMP packet with TTL=1
packet = IP(dst=target_ip, ttl=1) / ICMP()
# Send the packet
send(packet)

