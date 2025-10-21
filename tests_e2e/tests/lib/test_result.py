from tests_e2e.tests.lib.shell import CommandError


class TestSkipped(Exception):
    """
    Tests can raise this exception to indicate they should not be executed (for example, if trying to execute them on
    an unsupported distro
    """


class RemoteTestError(CommandError):
    """
    Raised when a remote test fails with an unexpected error.
    """