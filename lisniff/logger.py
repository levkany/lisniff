import logging
from lisniff import config


class CustomFormatter(logging.Formatter):
    def __init__(self, format:str):
        self.__grey = "\x1b[38;20m"
        self.__yellow = "\x1b[33;20m"
        self.__red = "\x1b[31;20m"
        self.__bold_red = "\x1b[31;1m"
        self.__reset = "\x1b[0m"
        self.__format = format
        self.__formats = {
            logging.DEBUG: self.__grey + self.__format + self.__reset,
            logging.INFO: self.__grey + self.__format + self.__reset,
            logging.WARNING: self.__yellow + self.__format + self.__reset,
            logging.ERROR: self.__red + self.__format + self.__reset,
            logging.CRITICAL: self.__bold_red + self.__format + self.__reset
        }

    def format(self, record):
        log_fmt = self.__formats.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
    

lisniff_logger_handler = logging.StreamHandler()
lisniff_logger_formatter = CustomFormatter(config.LOGGER_FORMAT)
lisniff_logger_handler.setFormatter(lisniff_logger_formatter)
lisniff_logger = logging.Logger(config.LOGGER_NAME, config.LOGGER_LEVEL)
lisniff_logger.addHandler(lisniff_logger_handler)
