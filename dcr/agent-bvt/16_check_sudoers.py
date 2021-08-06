import sys
import os


def main():
    found = False
    exit_code = 0
    root = '/etc/sudoers.d/'
    user = 'edp'

    for f in os.listdir(root):
        sudoers = os.path.join(root, f)
        with open(sudoers) as fh:
            for entry in fh.readlines():
                if entry.startswith(user) and 'ALL=(ALL)' in entry:
                    print('entry found: {0}'.format(entry))
                    found = True

    if not found:
        print('user {0} not found'.format(user))
        exit_code += 1

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
