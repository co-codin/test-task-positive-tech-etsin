import argparse
import multiprocessing

SOCK_BUFFER_SIZE = 1024 * 1024  # 1 MB
MAX_UDP_PACKET_SIZE = 65507  # Max size for UDP
MAX_TCP_PACKET_SIZE = 1024 * 1024  # 1MB for TCP
MAX_HTTP_PACKET_SIZE = 1024  # 1KB for HTTP(S)


def parse_ports(port_input):
    """Parse a port input as single, range, or multiple ports."""
    try:
        if '-' in port_input:
            start, end = map(int, port_input.split('-'))
            return list(range(start, end + 1))
        elif ',' in port_input:
            return list(map(int, port_input.split(',')))
        else:
            return [int(port_input)]
    except ValueError as e:
        print(f"[ERROR] Exception parsing ports: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description='ddos',
        usage="%(prog)s -ip <TARGET_IP> -p <PORT> [options]"
    )
    parser.add_argument('-ip', required=True, help='Target IP address')
    parser.add_argument('-p', help='Target port (can be a single port, range, or multiple ports)')
    parser.add_argument('-T', action='store_true', help='Use TCP protocol')
    parser.add_argument('-H', action='store_true', help='Use HTTP protocol')
    parser.add_argument('-S', action='store_true', help='Use HTTPS protocol')
    parser.add_argument('-I', action='store_true', help='Use ICMP protocol')
    parser.add_argument('-U', action='store_true', help='Use UDP protocol')
    parser.add_argument('-A', action='store_true', help='Run all protocols in parallel')
    parser.add_argument('-pr', default=30, type=int, help='Number of processes to run in parallel')
    parser.add_argument('-t', default=40, type=int, help='Number of threads per process')
    parser.add_argument('-ps', default=MAX_UDP_PACKET_SIZE, type=int, help='Packet size for the stress test')

    args = parser.parse_args()
    ip_address = args.ip
    num_processes = args.pr
    num_threads_per_process = args.t
    packet_size = args.ps

    protocols = []
    ports = {}

    if args.A:
        if args.p:
            port_list = parse_ports(args.p)
            protocols = ['TCP', 'UDP', 'ICMP', 'HTTPS', 'HTTP']
            for protocol in protocols:
                ports[protocol] = port_list if protocol != 'ICMP' else [0]
    else:
        if args.T: protocols.append('TCP')
        if args.U: protocols.append('UDP')
        if args.I: protocols.append('ICMP')
        if args.H: protocols.append('HTTP')
        if args.S: protocols.append('HTTPS')

        if args.p:
            for protocol in protocols:
                ports[protocol] = parse_ports(args.p)

    for protocol in protocols:
        for port in ports.get(protocol, []):
            processes = []
            for _ in range(num_processes):
                pass
