import os


def test_agent_log():
    agent_log_file = "/var/log/waagent.log"
    assert os.path.exists(agent_log_file), "No log file found"

    errors = []
    with open(agent_log_file, "r") as log_file:
        for line in log_file.readlines():
            if "ERROR" in line:
                errors.append(line.strip())

    assert len(errors) == 0, "Errors found in log:\n{0}".format('\n'.join(errors))
