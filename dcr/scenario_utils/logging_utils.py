# Create a base class
import logging


def get_logger(name):
    return LoggingHandler(name).log


class LoggingHandler:
    """
    Base class for Logging
    """
    def __init__(self, name=None):
        self.log = self.__setup_and_get_logger(name)

    def __setup_and_get_logger(self, name):
        logger = logging.getLogger(name if name is not None else self.__class__.__name__)
        if logger.hasHandlers():
            # Logging module inherits from base loggers if already setup, if a base logger found, reuse that
            return logger

        # No handlers found for logger, set it up
        # This logging format is easier to read on the DevOps UI -
        # https://docs.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops&tabs=bash#formatting-commands
        log_formatter = logging.Formatter("##[%(levelname)s] [%(asctime)s] [%(module)s] {%(pathname)s:%(lineno)d} %(message)s",
                                          datefmt="%Y-%m-%dT%H:%M:%S%z")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)

        return logger

