# pktsniffer

A packet sniffer created using the Scapy library. It reads in a .pcap file 
(generated from wireshark) and displays the packet headers based on the users commands

Running the code:
  1. Create a venv using python -m venv /path/to/new/virtual/environment
  2. Activate the venv using .\venv\Scripts\activate.bat
  3. Install the requirements using pip install -r requirements.txt
  3. run the code with through the terminal with python pktsniffer.py -r packets.pcapng

usage: pktsniffer.py [-h] [-r R] [-c C] [filter ...]

positional arguments:
  filter      filter types port, ip, tcp, udp, icmp, net

options:
  -h, --help  show this help message and exit
  -r R        The pcap file being read
  -c C        The number of packets being read

  Example commands:
  all packets      python pktsniffer.py -r packets.pcapng
  First 3          python pktsniffer.py -r packets.pcapng -c 3
  only TCP         python pktsniffer.py -r packets.pcapng tcp
  IP Address       python pktsniffer.py -r packets.pcapng net 192.168
  Port number      python pktsniffer.py -r packets.pcapng port 51365