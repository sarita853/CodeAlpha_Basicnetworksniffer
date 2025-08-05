from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"=== Packet Captured ===")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

            payload = bytes(tcp_layer.payload)
            if payload:
                # Print payload in hex format (first 50 bytes max)
                hex_payload = payload[:50].hex()
                print(f"Payload (hex, first 50 bytes): {hex_payload}")

                # Print payload in ASCII (non-printable chars replaced by '.')
                ascii_payload = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in payload[:50]])
                print(f"Payload (ascii, first 50 bytes): {ascii_payload}")
            else:
                print("Payload: <No data>")
        else:
            print("No TCP layer found in this packet.")
        print()

print("🔍 Starting packet sniffing... Press Ctrl+C to stop.")
# Sniff 10 TCP packets (you can change count or remove it for continuous sniff)
sniff(filter="tcp", prn=packet_callback, count=10)
