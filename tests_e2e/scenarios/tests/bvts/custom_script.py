import argparse
import os
import uuid
import sys

from tests_e2e.scenarios.modules.CustomScriptExtension import CustomScriptExtension


def main(subscription_id, resource_group_name, vm_name):
    os.environ["VMNAME"] = vm_name
    os.environ['RGNAME'] = resource_group_name
    os.environ["SUBID"] = subscription_id
    os.environ["SCENARIONAME"] = "BVT"
    os.environ["LOCATION"] = "westus2"
    os.environ["ADMINUSERNAME"] = "somebody"
    os.environ["BUILD_SOURCESDIRECTORY"] = "/somewhere"

    cse = CustomScriptExtension(extension_name="testCSE")

    ext_props = [
        cse.get_ext_props(settings={'commandToExecute': f"echo \'Hello World! {uuid.uuid4()} \'"}),
        cse.get_ext_props(settings={'commandToExecute': "echo \'Hello again\'"})
    ]

    cse.run(ext_props=ext_props)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--subscription')
        parser.add_argument('--group')
        parser.add_argument('--vm')

        args = parser.parse_args()

        main(args.subscription, args.group, args.vm)

    except Exception as exception:
        print(str(exception))
        sys.exit(1)

    sys.exit(0)


