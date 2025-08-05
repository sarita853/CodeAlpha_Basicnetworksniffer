Simple Packet Sniffer using Scapy
This is a basic network packet sniffer written in Python using the Scapy library.
It captures TCP packets from the network and prints important information like:

Source IP address
Destination IP address
Protocol
Source and destination ports
Payload data (in hex and ASCII format)

📌 Requirements
Make sure you have Python and Scapy installed.

Install Scapy using pip:
bash
Copy
Edit
pip install scapy
🚀 How to Run
Run the Python script using:
bash
Copy
Edit
sudo python your_script_name.py
⚠️ Note: You may need to run the script with sudo to allow packet sniffing.

🔍 What It Does
For each TCP packet it captures, the script:

Prints source and destination IP addresses.

Shows the IP protocol used.

If it’s a TCP packet:

Shows source and destination ports.

Displays the payload (first 50 bytes) in both hex and ASCII format.

If there's no payload, it prints <No data>.

🛑 How to Stop
The script is set to capture 10 TCP packets. It will automatically stop after that.
You can change the number of packets by modifying this line:

python
Copy
Edit
sniff(filter="tcp", prn=packet_callback, count=10)
Or remove count=10 to run it continuously (press Ctrl + C to stop manually).

🖼️ Sample Output
yaml
Copy
Edit
=== Packet Captured ===
Source IP: 192.168.1.10
Destination IP: 172.217.3.110
Protocol: 6
Source Port: 54321
Destination Port: 80
Payload (hex, first 50 bytes): 474554202f20485454502f312e310d0a486f73
Payload (ascii, first 50 bytes): GET / HTTP/1.1..Hos
📚 Notes
This script is for educational purposes and basic packet analysis.

Works best on Linux or macOS (may need admin privileges).

Use responsibly on networks you are authorized to monitor.

