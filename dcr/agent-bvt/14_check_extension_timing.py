from __future__ import print_function

import sys
import re

from dungeon_crawler.scenarios_utils.agent_log_parser import parse_agent_log_file, GOAL_STATE_COMPLETED

extension_name_pattern = r'\[(\S*)\]'

# 2018/05/22 21:23:32.888949 INFO [Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux-1.6.42.0] Target handler state: enabled
handle_extensions_starting_pattern = r'Target handler state:\s(\S*)'

extension_cycle = {0: '', 1: ''}

cycle_completed = False


def update_cycle(pos, name, when, info):
    global extension_cycle
    global cycle_completed

    extension_cycle[pos] = '@trace {0} {1} [{2}]'.format(when, name, info)

    for i in range(pos+1, 2):
        extension_cycle[i] = ''

    if all(i != '' for i in extension_cycle.values()):
        for key in extension_cycle.keys():
            print(extension_cycle[key])
        extension_cycle = {}
        cycle_completed = True


def main():

    exit_code = 0

    try:
        for agent_log_line in parse_agent_log_file():
            match = re.match(handle_extensions_starting_pattern, agent_log_line.message)
            if match:
                op = match.groups()[0]
                match = re.match(extension_name_pattern, agent_log_line.who)
                ext_name = match.groups()[0] if match else "invalid.extension.name.syntax"
                trans_op = "add/update" if op == "enabled" else "remove"
                info = "{0}: {1}".format(ext_name, trans_op)
                update_cycle(0, 'handle_extension_started', agent_log_line.when, info)
                continue

            match = re.match(GOAL_STATE_COMPLETED, agent_log_line.message)
            if match:
                duration = match.group('duration')
                update_cycle(1, 'handle_extension_duration', agent_log_line.when, duration)

    except IOError as e:
        print(e)
        sys.exit(127)

    if not cycle_completed:
        print('full cycle not completed')
        exit_code += 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
