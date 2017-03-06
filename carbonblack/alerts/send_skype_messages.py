import socket
from Skype4Py import Skype


serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('localhost', 9999))
serversocket.listen(5)
# Add the recipients
recipients = []

skype_connection = Skype()
# Attach to logged in Skype instance.
skype_connection.Attach()

while True:
    connection, address = serversocket.accept()
    buf = connection.recv(10000)
    if buf:
        message = (buf.decode("utf-8"))
        for recipient in recipients:
            skype_connection.SendMessage(recipient, message)
            print("Sent message to {}".format(recipient))
        continue
