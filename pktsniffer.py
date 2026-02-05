from scapy.all import rdpcap
from scapy.layers.l2 import Ether
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', help='The pcap file being read')
    parser.add_argument('-c', type=int, help='The number of packets being read')
    parser.add_argument('filter', nargs='*',
                        help='filter types port, ip, tcp, udp, icmp, net')
    return parser.parse_args()

def get_ethernet_header(packet):
    if packet.haslayer(Ether):
        print(f'src:  {packet[Ether].src}')
        print(f'dst:  {packet[Ether].dst}')
        print(f'Packet Length: {len(packet)} bytes')
        print(f'Ether Type: {(packet[Ether].type)} \n')


def main():
    args = get_args()
    packets = rdpcap(args.r)
    if args.c:
        packets = packets[:args.c]
    for p in packets:
        get_ethernet_header(p)
if __name__ == '__main__':
    main()
