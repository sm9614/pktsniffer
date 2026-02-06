from scapy.all import rdpcap
from scapy.layers.l2 import Ether
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', help='The pcap file being read')
    parser.add_argument(
        '-c', type=int, help='The number of packets being read')
    parser.add_argument('filter', nargs='*',
                        help='filter types port, ip, tcp, udp, icmp, net')
    return parser.parse_args()


def print_ethernet_header(packet):
    if packet.haslayer(Ether):
        print('Ethernet Header:')
        print(f'src:  {packet[Ether].src}')
        print(f'dst:  {packet[Ether].dst}')
        print(f'Packet Length: {len(packet)} bytes')
        print(f'Ether Type: {(packet[Ether].type)}')


def print_ip_header(packet):
    if packet.haslayer('IP'):
        ip = packet['IP']
        print('IP Header:')
        print(f'Version: {ip.version}')
        print(f'Header Length: {ip.ihl * 4} bytes')
        print(f'Service Type: {ip.tos}')
        print(f'Total Length: {ip.len * 4} bytes')
        print(f'Identification: {ip.id}')
        print(f'Flags: {ip.flags}')
        print(f'Fragment Offset: {ip.frag}')
        print(f'Time to Live: {ip.ttl}')
        print(f'Protocol: {ip.proto}')
        print(f'Header Checksum: {ip.chksum}')
        print(f'Source Address: {ip.src}')
        print(f'Destination Address: {ip.dst}')


def main():
    args = get_args()
    packets = rdpcap(args.r)
    if args.c:
        packets = packets[:args.c]
    for p in packets:
        print_ethernet_header(p)
        print_ip_header(p)


if __name__ == '__main__':
    main()
