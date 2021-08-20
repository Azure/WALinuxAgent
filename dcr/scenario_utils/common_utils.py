import subprocess


def execute_command_and_raise_on_error(command, shell=False, timeout=None):
    pipe = subprocess.Popen(command, shell=shell,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, stderr = pipe.communicate(timeout=timeout)

    print("STDOUT:\n{0}".format(stdout.decode()))
    print("STDERR:\n{0}".format(stderr.decode()))
    if pipe.returncode != 0:
        raise Exception("non-0 exit code: {0} for command: {1}".format(pipe.returncode, command))

    return stdout.decode().strip(), stderr.decode().strip()

