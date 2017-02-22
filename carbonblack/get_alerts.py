#!/usr/bin/env python3
from cb_framework import CBAlert, CbProcess, CbGoLive
import cb_logger
import logging
import os
import requests
import multiprocessing
import socket
import platform
import json
import time
import pickle
import argparse
import ntpath

__author__ = "Andrew Callow"
__copyright__ = "Andrew Callow"
__title__ = "get_alerts.py"
__license__ = "Proprietary"
__version__ = "1.0"
__email__ = "acallow@btinternet.com"
__status__ = "Prototype"


def alert_handler():
    """Looks for unresolved alerts and gets all proc data"""
    # Get the platform and clear screen command.
    if platform.system() == "Windows":
        cls_command = "cls"
    else:
        cls_command = "clear"

    # Create instance of CBAlert class.
    cb_alert = CBAlert(cb_api_key=arguments.cbapikey, cb_server_url=arguments.cbserverurl,
                       watchlist_name=arguments.watchlist)
    while True:
        cb_alert.get_alerts()

        # See if we have alerts.
        if cb_alert.watchlist_process_hits:
            process_alert_processor(data=cb_alert.watchlist_process_hits)

        if cb_alert.watchlist_binary_hits:
            binary_alert_processor(data=cb_alert.watchlist_binary_hits)

        # Sleep for 10 seconds.
        print("Alert checker is sleeping...")
        time.sleep(10)
        # Clear the screen.
        os.system(cls_command)


def process_alert_processor(data=None):
    """Handle the alerts we need to be triaged with process data collection and file collection"""
    # Get the already processed alerts.
    alerts_already_processed = get_completed_alerts()
    # List to store the system names with alerts (for later go_live).
    hosts_for_triage = []
    # Store the alerts to send.
    process_alerts_to_send = {}
    # Store the alerts that we need to process.
    to_process = {}
    # Loop through alerts.
    for watchlist in data:
        # Store the alerts.
        alerts = data[watchlist]["hits"]
        # Do if we have alerts.
        if alerts:
            # Loop through the hits for each alert.
            for hit in alerts:
                # Filter old alerts and store new ones.
                unique_id = hit["unique_id"]
                if unique_id not in alerts_already_processed:
                    # Check if we have a key for the watchlist name. If not, create an empty list.
                    if watchlist not in process_alerts_to_send:
                        process_alerts_to_send[watchlist] = []
                    # Add the alert to the list to be sent.
                    process_alerts_to_send[watchlist].append(hit)
                    # Add the new alert IDs (these are written to disk later).
                    alerts_already_processed.append(hit["unique_id"])
                    # Add the name of the host that needs triaging.
                    hosts_for_triage.append(hit["hostname"])
                    # Cat the process and segment ID and add to the list of things to process.
                    if watchlist not in to_process:
                        to_process[watchlist] = []
                    to_process[watchlist].append(str(hit["process_id"]) + "/" + str(hit["segment_id"]))

    # Send the alerts first and do the heavy lifting after.
    if process_alerts_to_send:
        send_process_alerts(process_alerts_to_send)
        # Write all newly processed alerts if we need to (old and new).
        update_completed_alerts(completed_alerts=alerts_already_processed)

    # Get all process data if we have events that have not already been processed.
    if to_process:
        # Loop through each watchlist.
        for watchlist in to_process:
            # Get the already completed procs.
            processes_already_processed = get_completed_procs()
            # Process the data
            process = CbProcess(cb_api_key=arguments.cbapikey, cb_server_url=arguments.cbserverurl,
                                cb_output_path=arguments.outputdir, process_ids=to_process[watchlist],
                                completed_procs=processes_already_processed)

            # Create a report if the proc data was collected.
            if process.process_data_store:
                # Create a report if we have a successful result.
                process.create_process_report(processes=process.process_data_store, title=watchlist)
                # Update the completed proc ids (old and new).
                update_completed_procs(completed_procs=process.completed_process_segments)

    # Triage the systems that need to be triaged LAST.
    if hosts_for_triage:
        hosts_for_triage = list(set(hosts_for_triage))
        triage_handler(hosts_for_triage)


def binary_alert_processor(data=None):
    """For processing unsigned binary alerts"""
    binary_alerts_to_send = {}
    alerts_already_processed = get_completed_alerts()
    for watchlist in data:
        for hit in data[watchlist]["hits"]:
            unique_id = hit["unique_id"]
            if unique_id not in alerts_already_processed:
                if watchlist not in binary_alerts_to_send:
                    binary_alerts_to_send[watchlist] = []
                binary_alerts_to_send[watchlist].append(hit)
                alerts_already_processed.append(hit["unique_id"])

    if binary_alerts_to_send:
        send_binary_alerts(binary_alerts_to_send)
        update_completed_alerts(completed_alerts=alerts_already_processed)


def send_process_alerts(alerts):
    """Formats the alerts and sends them to a local listener, which then forwards the alerts via Skype."""
    # Format the alerts banner.
    banner = "#" * 50
    disclaimer = "DISCLAIMER: In instances where multiple alerting hosts are seen, numbers assigned to each section " \
                 "above do not necessarily correlate to each other."
    # Loop through the received alerts and create a dictionary array.
    for use_case in alerts:
        collected_data = {"affected_hosts": [], "alert_path": [], "alert_count": len(alerts[use_case]),
                          "alert_time": [], "affected_users": [], "highlights": []}
        for alert in alerts[use_case]:
            collected_data["affected_hosts"].append(alert["hostname"])
            collected_data["alert_path"].append(alert["process_path"])
            collected_data["alert_time"].append(alert["created_time"])
            collected_data["affected_users"].append(alert["username"])
            # Parse the JSON highlights structure.
            try:
                highlights = json.loads(alert["ioc_attr"])
                for item in highlights["highlights"]:
                    highlight = item.replace("PREPREPRE", "").replace("POSTPOSTPOST", "")
                    collected_data["highlights"].append(highlight)
            except KeyError:
                collected_data["highlights"].append("NO ALERT HIGHLIGHTS/NO MORE ALERT HIGHLIGHTS")

        # De-dupe.
        users_data = sorted(list(set(collected_data["affected_users"])))
        hosts_data = sorted(list(set(collected_data["affected_hosts"])))
        paths_data = sorted(list(set(collected_data["alert_path"])))
        highlights_data = sorted(list(set(collected_data["highlights"])))

        # Build the unique users, hosts, paths and highlights.
        users = ""
        if len(users_data) > 10:
            users += "Showing 10 of {} affected users:\n".format(len(users_data))
            for i in range(10):
                users += "{}) {}\n".format(i + 1, users_data[i])
        else:
            for index, user in enumerate(users_data, 1):
                users += "{}) {}\n".format(index, user)

        hosts = ""
        if len(hosts_data) > 10:
            users += "Showing 10 of {} affected hosts:\n".format(len(hosts_data))
            for i in range(10):
                hosts += "{}) {}\n".format(i + 1, hosts_data[i])
        else:
            for index, host in enumerate(hosts_data, 1):
                hosts += "{}) {}\n".format(index, host)

        paths = ""
        if len(paths_data) > 10:
            paths += "Showing 10 of {} alert paths:\n".format(len(paths_data))
            for i in range(10):
                paths += "{}) {}\n".format(i + 1, paths_data[i])
        else:
            for index, path in enumerate(paths_data, 1):
                paths += "{}) {}\n".format(index, path)

        highlights = ""
        if len(highlights_data) > 10:
            paths += "Showing 10 of {} alert highlights:\n".format(len(highlights_data))
            for i in range(10):
                highlights += "{}) {}\n".format(i + 1, highlights_data[i])
        else:
            for index, highlight in enumerate(highlights_data, 1):
                highlights += "{}) {}\n".format(index, highlight)

        # Format the message to be sent.
        message = "{7}\n{0} New Process alert(s)!\nWatchlist Name: {1}\n{7}\n\nAlert Times:" \
                  " Between {2} and {3}\n\nAlerting Hosts:\n{4}\nAlert Paths:\n{5}\nAlert Highlights (as provided" \
                  " by the CB server - usually command line arguments): " \
                  "\n{8}\nAffected User Accounts:\n{6}\n{9}"\
            .format(collected_data["alert_count"], use_case, collected_data["alert_time"][0],
                    collected_data["alert_time"][-1], hosts, paths, users, banner, highlights, disclaimer)

        # Send the message to the local listener.
        try:
            clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsocket.connect(('localhost', 9999))
            clientsocket.sendall(bytes(message, "utf-8"))
            clientsocket.shutdown(socket.SHUT_WR)
        except ConnectionRefusedError:
            logging.info("There is no local alert listener running!")


def send_binary_alerts(alerts):
    """Formats the alerts and sends them to a local listener, which then forwards the alerts via Skype."""
    for use_case in alerts:
        for alert in alerts[use_case]:
            alert_watchlist_name = alert["watchlist_name"]
            alert_created_time = alert["created_time"]
            alert_hostname = alert["hostname"]
            alert_md5 = alert["md5"]
            alert_observed_file_names = [file_name for file_name in alert["observed_filename"]]
            alert_observed_hosts = []

            # Get the observed hosts.
            for observed_host in alert["observed_hosts"]["hostnames"]:
                alert_observed_hosts.append(observed_host["name"])

            # Get the alert highlights.
            try:
                alert_highlights = json.loads(alert["ioc_attr"])
                alert_highlights_data = []
                for item in alert_highlights["highlights"]:
                    highlight = item.replace("PREPREPRE", "").replace("POSTPOSTPOST", "")
                    alert_highlights_data.append(highlight)
            except KeyError:
                alert_highlights_data = ["NO ALERT HIGHLIGHTS"]

            # Format the alerts banner.
            banner = "#" * 50

            # Build the unique users, hosts, paths and highlights.
            observed_file_names = ""
            if len(alert_observed_file_names) > 10:
                observed_file_names += "Showing 10 of {} observed file names:\n"\
                    .format(len(alert_observed_file_names))
                for i in range(10):
                    observed_file_names += "{}) {}\n".format(i + 1, alert_observed_file_names[i])
            else:
                for index, name in enumerate(alert_observed_file_names, 1):
                    observed_file_names += "{}) {}\n".format(index, name)

            observed_hosts = ""
            if len(alert_observed_hosts) > 10:
                observed_hosts += "Showing 10 of {} affected hosts:\n".format(len(alert_observed_hosts))
                for i in range(10):
                    observed_hosts += "{}) {}\n".format(i + 1, alert_observed_hosts[i])
            else:
                for index, host in enumerate(alert_observed_hosts, 1):
                    observed_hosts += "{}) {}\n".format(index, host)

            highlights = ""
            for index, highlight in enumerate(alert_highlights_data, 1):
                highlights += "{}) {}\n".format(index, highlight)

            virus_check = vt_connect(alert_md5)
            # See if result = no hits.
            if not virus_check:
                vt_summary = "No hits on Virus Total for the MD5: {}".format(alert_md5)
                message = "{8}\nNew Binary alert!\nWatchlist Name: {0}\n{8}\n\nAlert Time: {1}\n\nHost: {2}\n\nMD5: " \
                          "{3}\n\nAll Observed file names for this binary:\n{4}\nAll Observed Hosts for " \
                          "this binary: \n{5}\nAlert Highlights (usually the path and signature status):" \
                          "\n{6}\nVirus Total Scan:\n{7}" \
                    .format(alert_watchlist_name, alert_created_time, alert_hostname, alert_md5, observed_file_names,
                            observed_hosts, highlights, vt_summary, banner)

            # If we have a connection failure.
            elif type(virus_check) == str:
                message = "{8}\nNew Binary alert!\nWatchlist Name: {0}\n{8}\n\nAlert Time: {1}\n\nHost: {2}" \
                          "\n\nMD5: {3}\n\nAll Observed file names for this binary:\n{4}\n" \
                          "All Observed Hosts for this binary:\n{5}\nAlert Highlights (usually the path and signature" \
                          " status):\n{6}\nVirus Total Scan:\n{7}"\
                    .format(alert_watchlist_name, alert_created_time, alert_hostname, alert_md5, observed_file_names,
                            observed_hosts, highlights, virus_check, banner)

            # Result = known, but with no malicious detections.
            elif not virus_check[1]:
                vt_summary = virus_check[0]
                vt_link = virus_check[2]
                message = "{9}\nNew Binary alert!\nWatchlist Name: {0}\n{9}\n\nAlert Time: {1}\n\nHost: {2}\n\nMD5:" \
                          " {3}\n\nAll Observed file names for this binary:\n{4}\nAll Observed Hosts for this binary:" \
                          "\n{5}\nAlert Highlights (usually the path and signature status):" \
                          "\n{6}\nVirus Total Scan:\n{7}\n{8}" \
                    .format(alert_watchlist_name, alert_created_time, alert_hostname, alert_md5, observed_file_names,
                            observed_hosts, highlights, vt_link, vt_summary, banner)

            # Results = Known plus malicious detections.
            else:
                vt_summary = virus_check[0]
                vt_results = virus_check[1]
                vt_link = virus_check[2]
                message = "{10}\nNew Binary alert!\nWatchlist Name: {0}\n{10}\n\nAlert Time: {1}\n\nHost: {2}" \
                          "\n\nMD5: {3}\n\nAll Observed file names for this binary:\n{4}\nAll Observed " \
                          "Hosts for this binary:\n{5}\nAlert Highlights (usually the path and signature status):" \
                          "\n{6}\nVirus Total Scan:\n{7}\n{8}\n{9}"\
                    .format(alert_watchlist_name, alert_created_time, alert_hostname, alert_md5, observed_file_names,
                            observed_hosts, highlights, vt_link, vt_summary, vt_results, banner)

            # Send the message to the local listener.
            try:
                clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clientsocket.connect(('localhost', 9999))
                clientsocket.sendall(bytes(message, "utf-8"))
                clientsocket.shutdown(socket.SHUT_WR)
            except ConnectionRefusedError:
                logging.error("There is no local alert listener running!")

            time.sleep(5)


def triage_handler(hosts):
    """Processes go live actions."""
    # Create instance of CBGolive class.
    sensors = CbGoLive(*go_live_args)
    # Get sensor details.
    sensors.get_sensor_details()
    # Shortcut for online list.
    online = sensors.online_sensors

    # This ist stores the system ID and host name, which is needed to make the golive conn.
    to_process = []
    for system in online:
        for host in hosts:
            if system["computer_name"].lower() == host.lower():
                # Store elements in tuple.
                to_process.append((system["id"], system["computer_name"], system["os_environment_display_string"]))

    if not to_process:
        logging.info("None of the hosts with alerts are online, so go_live data can't be collected!")
        return
    else:
        # Get the files to be collected.
        with open(arguments.filestoget, "r", encoding="utf-8") as files_to_get:
            files = [line.strip() for line in files_to_get if line]

        # Handle the multiprocessing.
        while to_process:
            if len(to_process) < 5:
                procs = len(to_process)
            else:
                procs = 5
            to_do = [[to_process[i][0], to_process[i][1], to_process[i][2],
                      files, arguments.sevenzipx86path, arguments.sevenzipx64path, go_live_args] for i in range(procs)]
            p = multiprocessing.Pool(procs)
            p.map(do_triage, to_do)
            p.close()
            p.join()
            for i in range(procs):
                del to_process[0]


def do_triage(system_details):
    """Do the actual triaging"""
    lock = multiprocessing.Lock()  # Instantiate a threading lock instance.
    # Unpack the item in queue.
    sensor_id, host, os_version, files_to_get, sevenzipx86path, sevenzipx64path, args = system_details
    # Get the 7zip version.
    if "64-bit" in os_version:
        zip_path = sevenzipx64path
    else:
        zip_path = sevenzipx86path
    # Create a logger.
    if platform.system() == "Windows":
        cb_logger.logger(args[2])
    # Lock the thread so that we do not have multiple simultaneous access to CBGoLive's class attributes.
    lock.acquire()
    # Instantiate new instance of CbGoLive.
    new_triage = CbGoLive(*args)
    # Release the lock.
    lock.release()
    # Setup a go live session and do stuff.
    new_triage.setup_go_live_session(sensor_id=sensor_id, host=host, override_existing_session=False)

    # Do this if we have a new session
    if new_triage.go_live_session_status:
        # Get the 7zip files to put
        files_to_put = []
        for path, dirs, files in os.walk(zip_path):
            for filename in files:
                fullpath = os.path.join(path, filename)
                files_to_put.append((fullpath, filename))

        # upload the 7zip files.
        for file in files_to_put:
            fullpath, filename = file
            new_triage.put_file(file_to_put=fullpath, working_directory=r"c:\windows\carbonblack")

        # Copy the files to the carbon black directory (in case they are locked).
        for file in files_to_get:
            new_triage.execute_command(command="c:\\windows\\system32\\cmd.exe /c copy \"{}\" "
                                               "c:\\windows\\carbonblack\\"
                                       .format(file))

        # Add file to archive.
        for file in files_to_get:
            new_triage.execute_command(command="c:\\windows\\system32\\cmd.exe /c c:\\windows\\carbonblack\\7za.exe "
                                               "a -tzip triage.zip \"c:\\windows\\carbonblack\\{}\""
                                       .format(ntpath.split(file)[1]))

        # Get the archive.
        new_triage.get_file(file=r"c:\windows\carbonblack\triage.zip")

        # Delete the archive.
        new_triage.delete_file(file=r"c:\windows\carbonblack\triage.zip")

        # Delete the 7zip files.
        for file in files_to_put:
            fullpath, filename = file
            new_triage.delete_file(file=r"c:\windows\carbonblack\{}".format(filename))

        # Delete the copied logs.
        for file in files_to_get:
            new_triage.delete_file(file=r"c:\windows\carbonblack\{}".format(ntpath.split(file)[1]))

        # Close the session.
        new_triage.close_session()
        return
        # This is crucial else unsuccessful attempts will stall processing.
    else:
        return


def get_completed_procs():
    """Get the already completed procs"""
    if os.path.getsize(arguments.procsfile) != 0:
        with open(arguments.procsfile, "rb") as completed:
            processes_already_processed = pickle.load(completed)
    else:
        processes_already_processed = {}

    return processes_already_processed


def get_completed_alerts():
    """Get the already processed alerts"""
    if os.path.getsize(arguments.alertsfile) != 0:
        with open(arguments.alertsfile, "rb") as alert:
            alerts_already_processed = pickle.load(alert)
    else:
        alerts_already_processed = []

    return alerts_already_processed


def update_completed_procs(completed_procs=None):
    """Update the completed procs."""
    with open(arguments.procsfile, "wb") as completed:
        pickle.dump(completed_procs, completed)
    return


def update_completed_alerts(completed_alerts=None):
    """Update the completed alerts."""
    with open(arguments.alertsfile, "wb") as alerts:
        pickle.dump(completed_alerts, alerts)
    return


def vt_connect(md5):
    """Get VT information"""
    try:
        params = {"apikey": arguments.vtapikey, "resource": md5}
        query = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
                              params=params)
        try:
            json_response = query.json()
        except ValueError:
            return None

        http_response_code = query.status_code

        if http_response_code != 200:
            return "Connection to VT failed!"

        if json_response["response_code"] == 0:
            return None
    except requests.exceptions.ConnectionError:
        return "Connection to VT failed!"

    hits = []
    av_scans = len(json_response["scans"])
    for scan in json_response["scans"]:
        if json_response["scans"][scan]["detected"]:
            hits.append((scan, json_response["scans"][scan]["result"]))

    if hits:
        permalink = json_response["permalink"]
        summary = "{}/{} AV Vendors deem this file to be malicious. Details of the malicious hits are as follows:"\
            .format(len(hits), av_scans)

        hits_summary = ""
        for index, hit in enumerate(hits, 1):
            vendor, result = hit
            hits_summary += "{}) AV Engine: {}. Result: {}.\n".format(index, vendor, result)

        return [summary, hits_summary, permalink]

    else:
        permalink = json_response["permalink"]
        summary = "{}/{} AV Vendors deem this file to be malicious.".format(len(hits), av_scans)
        return [summary, None, permalink]

if __name__ == "__main__":
    # description of script
    description = """This script gets alerts from a selected Carbon Black server, sends them via Skype, collects
    all process data, and collects user specified files from the alerting system(s)."""

    # use case
    epilog = """example: -k 12345
    -u https://cbserver -w operation_name -a /home/sansforensics/Desktop/cb/alerts.p
    -p /home/sansforensics/Desktop/cb/processes.p -f /home/sansforensics/Desktop/cb/files.txt
    -o /home/sansforensics/Desktop/cb/alerts -v 6789 -e 7zip/x86 -s 7zip/x64"""

    # arguments
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument("--cbapikey", "-k",
                        action="store",
                        help="Your Carbon Black API key.",
                        required=True)
    parser.add_argument("--cbserverurl", "-u",
                        action="store",
                        help="The Carbon Black server's URL.",
                        required=True)
    parser.add_argument("--watchlist", "-w",
                        action="store",
                        help="The operation name that will appear in the title of each relevant watchlist",
                        required=True)
    parser.add_argument("--alertsfile", "-a",
                        action="store",
                        help="Location of the file containing already processed alerts.",
                        required=True)
    parser.add_argument("--procsfile", "-p",
                        action="store",
                        help="Location of the file containing completed procs.",
                        required=True)
    parser.add_argument("--filestoget", "-f",
                        action="store",
                        help="Location of file containing paths of files to get during Triage.",
                        required=True)
    parser.add_argument("--outputdir", "-o",
                        action="store",
                        help="Output directory for storing all logging/files.",
                        required=True)
    parser.add_argument("--sevenzipx86path", "-e",
                        action="store",
                        help="Path to 7zip x86 binaries.",
                        required=True)
    parser.add_argument("--sevenzipx64path", "-s",
                        action="store",
                        help="Path to 7zip x64 binaries.",
                        required=True)
    parser.add_argument("--vtapikey", "-v",
                        action="store",
                        help="Your Virus Total API Key.",
                        required=True)

    arguments = parser.parse_args()

    # Crate the output dir.
    if not os.path.exists(arguments.outputdir):
        os.makedirs(arguments.outputdir)

    # Create the alerts file (if we need to).
    if not os.path.exists(arguments.alertsfile):
        with open(arguments.alertsfile, "wb") as f:
            pass

    # Create the completed procs file (if we need to).
    if not os.path.exists(arguments.procsfile):
        with open(arguments.procsfile, "wb") as f:
            pass

    # Create the logger.
    cb_logger.logger(arguments.outputdir)
    # Set the CB Go Live args.
    go_live_args = [arguments.cbapikey, arguments.cbserverurl, arguments.outputdir]
    # Get the alerts.
    alert_handler()
