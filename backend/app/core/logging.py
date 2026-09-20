import logging
import sys
from typing import Optional


def configure_logging(log_level: str = 'INFO') -> logging.Logger:
    logger = logging.getLogger('cybershield')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                '%(asctime)s %(levelname)s %(name)s %(message)s'
            )
        )
        logger.addHandler(handler)

    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(f'cybershield.{name}' if name else 'cybershield')
