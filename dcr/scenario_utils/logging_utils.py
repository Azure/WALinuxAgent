# Create a base class
import logging


class LoggingHandler:
    """
    Base class for inheritance logging
    """
    def __init__(self, *args, **kwargs):
        self.log = logging.getLogger(self.__class__.__name__)
