# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import logging


def get_logger(name=None):
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

        log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)

        return logger

