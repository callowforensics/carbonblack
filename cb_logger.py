import logging
import os
import requests

__author__ = "Andrew Callow"
__copyright__ = "Andrew Callow"
__title__ = "cb_logger.py"
__license__ = "Proprietary"
__version__ = "1.0"
__email__ = "acallow@btinternet.com"
__status__ = "Prototype"


def logger(path):
    #  Create the logger.
    logging.basicConfig(format='%(asctime)s: %(levelname)s: %(message)s',
                        datefmt="%d/%m/%Y %I:%M:%S %p",
                        level=logging.DEBUG,
                        filename=os.path.join(path, "carbon_black_log.txt"))
    logging.getLogger("requests").setLevel(logging.WARNING)  # Set requests logging to warning only.
    console = logging.StreamHandler()  # Set up logging to console.
    console.setLevel(logging.CRITICAL)  # Set up logging to console
    formatter = logging.Formatter('%(levelname)s : %(message)s')  # Format which is simpler for console use
    console.setFormatter(formatter)  # Set console format.
    logging.getLogger("").addHandler(console)  # Add console handler.
    requests.packages.urllib3.disable_warnings()  # Disable insecure connection warnings.
