import argparse

SOCK_BUFFER_SIZE = 1024 * 1024  # 1 MB
MAX_UDP_PACKET_SIZE = 65507  # Max size for UDP
MAX_TCP_PACKET_SIZE = 1024 * 1024  # 1MB for TCP
MAX_HTTP_PACKET_SIZE = 1024  # 1KB for HTTP(S)

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