import socket
import sys

WIRESERVER_ENDPOINT_FILE = '/var/lib/waagent/WireServerEndpoint'
WIRESERVER_IP = '168.63.129.16'


def get_wireserver_ip() -> str:
    try:
        with open(WIRESERVER_ENDPOINT_FILE, 'r') as f:
            wireserver_ip = f.read()
    except Exception:
        wireserver_ip = WIRESERVER_IP
    return wireserver_ip


def main():
    try:
        wireserver_ip = get_wireserver_ip()
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((wireserver_ip, 53))

        print('Socket connection to wire server:53 success')
    except:  # pylint: disable=W0702
        print('Socket connection to wire server:53 failed')
        sys.exit(1)


if __name__ == "__main__":
    main()
