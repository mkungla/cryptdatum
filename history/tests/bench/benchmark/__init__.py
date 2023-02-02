# © 2023 Happy SDK Authors
# Apache License 2.0

"""Worker to collect and generate Cryptdatum benchmarks"""

import logging

from .benchmark import Benchmark
from .logger import LogFormatter

__all__ = ["new_bench", "get_logger"]

lh = logging.StreamHandler()
lh.setFormatter(LogFormatter())
logging.basicConfig(
    level=logging.NOTSET,
    handlers=[lh]
)

logger = logging.getLogger("bench")

def new_bench(level=logging.NOTSET) -> Benchmark:
  return Benchmark(get_logger(level))

def get_logger(level=logging.NOTSET) -> logging.Logger:
  logger.setLevel(level)
  return logger
