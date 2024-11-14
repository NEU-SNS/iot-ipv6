import logging
import sys

def setup_logger(logger_name, logger_file, level=logging.DEBUG):
    logger = logging.getLogger(logger_name)
    logging.basicConfig(filename=logger_file, filemode='a+', level=level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


    logger.info("----------------------------------")
    logger.info("---|| IoTv6 Project Analysis ||---")
    logger.info("----------------------------------")
    return logger