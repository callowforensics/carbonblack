**cb_framework.py:** 

Python 3 code for the low-level API interaction. This was written as a personal project, so the python wrapper that ships with CB  may be of better use. Full instructions regarding all clases/methods to follow.

**get_alerts.py:**

Python 3 code that checks for new alerts every 10 seconds, collects all process data in respect of them, connects to alerting hosts and downloads key files (zipped) and formats alert messages. Uses cb_framework.py.

**send_skype_alerts.py**

Python 2 code that listens for new alert messages (sent during the operation of get_alerts.py) and sends them via Skype. Works best with the Linux Skype client, as this still allows API calls as per those initiated from Skpye4Py. 

**cb_logger**

Python 3 code that creates a logger instance that writes to file and stdout.
