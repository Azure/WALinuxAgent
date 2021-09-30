# Create a base class
import logging


def get_logger(name):
    return LoggingHandler(name).log


class MyFormatter(logging.Formatter):
    def format(self, record):
        record.statement = "debug" if record.levelname in (logging.INFO, logging.DEBUG) else record.levelname.lower()
        return logging.Formatter.format(self, record)


class LoggingHandler:
    """
    Base class for inheritance logging
    """
    def __init__(self, name=None):
        # logging.basicConfig(level=logging.INFO)
        self.log = self.__setup_and_get_logger(name)

    def __setup_and_get_logger(self, name):
        logger = logging.getLogger(name if name is not None else self.__class__.__name__)
        if logger.hasHandlers():
            return logger

        # No handlers found for logger, set it up
        log_formatter = logging.Formatter("##[%(levelname)s] [%(asctime)s] [%(module)s] {%(pathname)s:%(lineno)d} %(message)s",
                                          datefmt="%Y-%m-%dT%H:%M:%S%z")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)

        return logger

