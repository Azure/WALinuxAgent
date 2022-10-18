from __future__ import print_function

import argparse
import subprocess
import sys


def main(subscription_id, resource_group_name, vm_name):
    pipe = subprocess.Popen(
        """az vm extension set --subscription {0} --resource-group {1} --vm-name {2} --name customScript --publisher Microsoft.Azure.Extensions --protected-settings '{{\"commandToExecute\": \"echo 1\"}}'""".format(
            subscription_id,
            resource_group_name,
            vm_name
        ),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    stdout, stderr = pipe.communicate()

    print(stdout, file=sys.stdout)
    print(stderr, file=sys.stderr)

    return pipe.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--subscription')
    parser.add_argument('--group')
    parser.add_argument('--vm')

    args = parser.parse_args()

    sys.exit(main(args.subscription, args.group, args.vm))


