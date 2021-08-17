import subprocess
import sys
import socket


def main():
    pipe = subprocess.Popen(['hostname'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    hostname = list(map(lambda s: s.decode('utf-8').strip(), pipe.stdout.readlines()))[0]
    if hostname[-1:] == '\n':
        hostname = hostname[:-1]

    print("Hostname: {0}".format(hostname))

    exit_code = 0
    try:
        ip = socket.gethostbyname(hostname)
        print("Resolved IP: {0}".format(ip))
    except Exception as e:
        print("[ERROR] Ran into exception: {0}".format(e))
        exit_code = 1

    print("'nslookup {0}' returned exit code '{1}'".format(hostname, exit_code))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
