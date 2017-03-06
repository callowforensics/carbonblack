#!/usr/bin/env python3
from cb_framework import CbGoLive
import csv
import sys
import os
from O365 import Message, Attachment
from time import gmtime, strftime

# Check that the user has enter enough args.
if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: cb_api_key cb_server_url output_dir senders_email_address recipients_list")
        print("\nExample:")
        print("-" * 50)
        print(r"abcdefghijklmnopqrstuvwxyz https://123.456.789.1 c:\output test@123.com c:\recipients.txt")
        sys.exit()

    cb_api = sys.argv[1]
    cb_url = sys.argv[2]
    output_dir = sys.argv[3]
    sender = sys.argv[4]
    recipients_file = sys.argv[5]

    with open(recipients_file, "r") as f:
        recipients = [line.strip() for line in f if line != "\n"]

    recipients = tuple(recipients)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    time_now = strftime("%d-%m-%Y", gmtime()).replace(" ", "_").replace(":", "-")
    output_file = os.path.join(output_dir, "cb_hosts_{}.csv".format(time_now))

    password = input("Please enter the password for the email account: {}: ".format(sender))

    authenticiation = (sender, password)

    sensors = CbGoLive(cb_api_key=cb_api, cb_server_url=cb_url, cb_output_path=output_dir)
    sensors.get_sensor_details()
    sensors = sensors.online_sensors + sensors.offline_sensors

    csv_header = []
    for key in sorted(sensors[0].keys()):
        csv_header.append(key)

    rows = []
    for sensor in sensors:
        row = [value for key, value in sorted(sensor.items())]
        rows.append(row)

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(csv_header)
        for row in rows:
            writer.writerow(row)

    m = Message(auth=authenticiation)
    att = Attachment(path=output_file)
    m.attachments.append(att)
    body = "Please find the attached daily Carbon Black Report."

    for recipient in recipients:
        m.setRecipients(recipient)
        m.setSubject("Carbon Black Report - {}".format(time_now))
        m.setBody(body)
        m.sendMessage()
