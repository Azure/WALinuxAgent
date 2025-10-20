from typing import Any


class CommandError(Exception):
    """
    Exception raised by run_command when the command returns an error
    """
    def __init__(self, command: Any, exit_code: int, stdout: str, stderr: str):
        super().__init__(f"'{command}' failed (exit code: {exit_code}): {stderr}")
        self.command: Any = command
        self.exit_code: int = exit_code
        self.stdout: str = stdout
        self.stderr: str = stderr

    def __str__(self):
        return f"'{self.command}' failed (exit code: {self.exit_code})\nstdout:\n{self.stdout}\nstderr:\n{self.stderr}\n"

class TestSkipped(Exception):
    """
    Tests can raise this exception to indicate they should not be executed (for example, if trying to execute them on
    an unsupported distro
    """


class RemoteTestError(CommandError):
    """
    Raised when a remote test fails with an unexpected error.
    """