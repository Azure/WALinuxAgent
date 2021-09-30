class CommandError(Exception):
    def __init__(self, command, exit_code, stdout, stderr):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        msg = f"Command {command} failed with exit code: {exit_code}.\n\tStdout: {stdout}\n\tStderr: {stderr}"
        super(CommandError, self).__init__(msg)