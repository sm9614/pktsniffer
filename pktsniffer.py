from scapy.all import rdpcap
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', help='The pcap file being read')
    parser.add_argument('c', type=int, help='The number of packets being read')
    parser.add_argument('filter', nargs='*',
                        help='filter types port, ip, tcp, udp, icmp, net')
    return parser

def main():
    args = parse_args()

if __name__ == '__main__':
    main()
