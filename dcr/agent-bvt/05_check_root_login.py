import subprocess
import sys


def main():
    pipe = subprocess.Popen(['cat', '/etc/shadow'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    std_out = map(lambda s: s.decode('utf-8'), pipe.stdout.readlines())
    exit_code = pipe.wait()
    root_passwd = [line for line in std_out if 'root' in line][0].split(":")[1]

    if exit_code != 0:
        sys.exit(exit_code)
    elif "!" in root_passwd or "*" in root_passwd:
        print('root login disabled')
        sys.exit(0)
    else:
        print('root login appears to be enabled: {0}'.format(root_passwd))
        sys.exit(1)


if __name__ == "__main__":
    main()
