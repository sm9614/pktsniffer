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
        ether = packet[Ether]
        print('Ethernet Header:')
        print(f'Packet Size: {len(packet)} bytes')
        print(f'Destination MAC address:  {ether.dst}')
        print(f'Source MAC address:  {ether.src}')
        print(f'Ether Type: {ether.type}\n')


def print_ip_header(packet):
    if packet.haslayer('IP'):
        ip = packet['IP']
        print('IP Header:')
        print(f'Version: {ip.version}')
        print(f'Header Length: {ip.ihl * 4} bytes')
        print(f'Service Type: {ip.tos}')
        print(f'Total Length: {ip.len} bytes')
        print(f'Identification: {ip.id}')
        print(f'Flags: {ip.flags}')
        print(f'Fragment Offset: {ip.frag}')
        print(f'Time to Live: {ip.ttl}')
        print(f'Protocol: {ip.proto}')
        print(f'Header Checksum: {ip.chksum}')
        print(f'Source Address: {ip.src}')
        print(f'Destination Address: {ip.dst}\n')


def print_tcp_header(packet):
    if packet.haslayer('TCP'):
        tcp = packet['TCP']
        print('TCP Header:')
        print(f'Source Port: {tcp.sport}')
        print(f'Destination Port: {tcp.dport}')
        print(f'Sequence Number: {tcp.seq}')
        print(f'Acknowledgment Number: {tcp.ack}')
        print(f'Data Offset: {tcp.dataofs}')
        print(f'Reserved: {tcp.reserved}')
        print(f'Header Length: {tcp.dataofs * 4} bytes')
        print(f'Flags: {tcp.flags}')
        print(f'Window Size: {tcp.window}')
        print(f'Checksum: {tcp.chksum}')
        print(f'Urgent Pointer: {tcp.urgptr}\n')


def print_udp_header(packet):
    if packet.haslayer('UDP'):
        udp = packet['UDP']
        print('UDP Header:')
        print(f'Source Port: {udp.sport}')
        print(f'Destination Port: {udp.dport}')
        print(f'Length: {udp.len} bytes')
        print(f'Checksum: {udp.chksum}\n')


def print_icmp_header(packet):
    if packet.haslayer('ICMP'):
        icmp = packet['ICMP']
        print('ICMP Header:')
        print(f'Type: {icmp.type}')
        print(f'Code: {icmp.code}')
        print(f'Checksum: {icmp.chksum}\n')


def filter_packets(packets, filter):
    filter_type = filter[0].lower()
    filtered_packets = []
    for p in packets:
        if filter_type == 'port':
            port_number = int(filter[1])

            if ((p.haslayer('TCP') and (p['TCP'].sport == port_number or p['TCP'].dport == port_number))
                    or (p.haslayer('UDP') and (p['UDP'].sport == port_number or p['UDP'].dport == port_number))):
                filtered_packets.append(p)

        elif filter_type == 'ip':
            if p.haslayer('IP'):
                filtered_packets.append(p)

        elif filter_type == 'tcp':
            if p.haslayer('TCP'):
                filtered_packets.append(p)

        elif filter_type == 'udp':
            if p.haslayer('UDP'):
                filtered_packets.append(p)

        elif filter_type == 'icmp':
            if p.haslayer('ICMP'):
                filtered_packets.append(p)

        elif filter_type == 'net':
            ip_address = filter[1]
            if p.haslayer('IP') and (p['IP'].src.startswith(ip_address) or p['IP'].dst.startswith(ip_address)):
                filtered_packets.append(p)

    return filtered_packets


def print_packets(packets, filter_type):
    for i, p in enumerate(packets, start=1):
        print(f'\n----------------Packet {i}----------------')
        print_ethernet_header(p)
        if filter_type == 'ip':
            print_ip_header(p)
        elif filter_type == 'tcp':
            print_tcp_header(p)
        elif filter_type == 'udp':
            print_udp_header(p)
        elif filter_type == 'icmp':
            print_icmp_header(p)
        elif filter_type == 'port':
            print_tcp_header(p)
            print_udp_header(p)
        elif filter_type == 'net':
            print_ip_header(p)
        else:
            print_ip_header(p)
            print_tcp_header(p)
            print_udp_header(p)
            print_icmp_header(p)


def main():
    args = get_args()
    packets = rdpcap(args.r)
    if args.c:
        packets = packets[:args.c]
        print_packets(packets, None)
    elif args.filter:
        filtered_packets = filter_packets(packets, args.filter)
        print_packets(filtered_packets, args.filter[0])
    else:
        print_packets(packets, None)


if __name__ == '__main__':
    main()
