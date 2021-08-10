import subprocess
import sys
import re

daemon_pattern = '.*python.*waagent -daemon$'
handler_pattern = '.*python.*-run-exthandlers'
status_pattern = '^(\S+)\s+'


def main():
    pipe = subprocess.Popen(['ps', 'axo', 'stat,args'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    std_out = map(lambda s: s.decode('utf-8'), pipe.stdout.readlines())
    exit_code = pipe.wait()

    if exit_code != 0:
        sys.exit(exit_code)

    daemon = False
    ext_handler = False
    agent_processes = [line for line in std_out if 'python' in line]
    for process in agent_processes:

        if re.match(daemon_pattern, process):
            daemon = True
        elif re.match(handler_pattern, process):
            ext_handler = True
        else:
            continue

        status = re.match(status_pattern, process).groups(1)[0]
        if status.startswith('S') or status.startswith('R'):
            pass
        else:
            print('process is not running: {0}'.format(process))
            sys.exit(1)

    if not daemon:
        print('daemon process not found:\n\n{0}'.format(std_out))
        sys.exit(2)
    if not ext_handler:
        print('extension handler process not found:\n\n{0}'.format(std_out))
        sys.exit(3)

    print('expected processes found running')
    sys.exit(0)


if __name__ == "__main__":
    main()
