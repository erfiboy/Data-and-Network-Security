import logging

logger = logging.getLogger(__name__)

c_handler = logging.FileHandler("file.log")
c_handler.setLevel(logging.INFO)

c_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)
