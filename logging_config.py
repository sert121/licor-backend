import logging
import logging.config
import os

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standardFormatter": {
            "format": "%(asctime)s %(levelname)s %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "securityFormatter": {
            "format": "%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "verboseFormatter": {
            "format": "%(asctime)s %(levelname)s %(module)s %(process)d %(thread)d %(filename)s:%(lineno)d %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "consoleHandler": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "standardFormatter",
            "stream": "ext://sys.stdout",
        },
        "fileHandler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "verboseFormatter",
            "filename": os.path.join(
                os.getcwd(), "logs", "gh_requests", "ndexai_gh_requests.log"
            ),
            "maxBytes": 1024 * 1024 * 5,  # 5 MB
            "backupCount": 5,
        },
    },
    "loggers": {
        "root": {"level": "WARNING", "handlers": ["consoleHandler", "fileHandler"]},
        "security": {
            "level": "INFO",
            "handlers": ["fileHandler"],
            "qualname": "security",
            "propagate": False,
        },
        "debug": {"level": "DEBUG", "handlers": ["consoleHandler"], "propagate": False},
    },
}

# Load the logging configuration
try:
    logging.config.dictConfig(LOGGING_CONFIG)
except ValueError as e:
    raise SystemExit(f"Error in logging configuration: {e}")

RootLogger = logging.getLogger("root")
SecurityLogger = logging.getLogger("security")
DebugLogger = logging.getLogger("debug")
