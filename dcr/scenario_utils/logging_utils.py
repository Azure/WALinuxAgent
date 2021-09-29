# Create a base class
import logging


def get_logger(name):
    return LoggingHandler(name).log


class LoggingHandler:
    """
    Base class for inheritance logging
    """
    def __init__(self, name=None):
        logging.basicConfig(level=logging.INFO)
        self.log = logging.getLogger(name if name is not None else self.__class__.__name__)
