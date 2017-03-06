#!/usr/bin/env python3
import requests
import time
import os
import sys
import logging
from cb_framework import CbGoLive
import cb_logger

if __name__ == "__main__":
    # Check that the user has enter enough args.
    if len(sys.argv) != 5:
        print("Usage: cb_api_key cb_server_url output_dir query")
        print("\nExample:")
        print("-" * 50)
        print("abcdefghijklmnopqrstuvwxyz https://123.456.789.1 c:\output testsys1 \"hostname:testsys "
              "process_name:notepad.exe\"")
        print("Note you must place the query within speech marks!")

        sys.exit()

    cb_api = sys.argv[1]
    cb_url = sys.argv[2]
    output_dir = sys.argv[3]
    query = sys.argv[4]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cb_logger.logger(output_dir)

    killed_in_session = {}
    while True:
        to_kill = {}
        # Set the payload.
        payload = {'q': query}

        # Make a query to the API using the search query, decode the JSON and store the "hit" count.
        result_count = requests.get("{}/api/v1/process".format(cb_url),
                                    params=payload,
                                    headers={"X-Auth-Token": cb_api},
                                    verify=False).json()["total_results"]

        if result_count == 0:
            time.sleep(10)
            continue

        # Set the 2nd search payload.
        payload2 = {'q': query, "rows": result_count}

        # Get the process details for each event.
        all_hits = requests.get("{}/api/v1/process".format(cb_url),
                                params=payload2,
                                headers={"X-Auth-Token": cb_api},
                                verify=False).json()["results"]

        for result in all_hits:
            if not result["terminated"]:
                host = result["hostname"]
                try:
                    if result["process_pid"] in killed_in_session[host]:
                        continue
                except KeyError:
                    pass
                if host not in to_kill:
                    to_kill[host] = {}
                    to_kill[host]["host"] = host
                    to_kill[host]["sensor_id"] = result["sensor_id"]
                    to_kill[host]["die!"] = []
                to_kill[host]["die!"].append((result["process_pid"], result["cmdline"], result["process_name"]))

        if to_kill:
            logging.info("We have PIDs to kill!")
            for host in to_kill:
                session = CbGoLive(cb_api_key=cb_api, cb_server_url=cb_url, cb_output_path=output_dir)
                session.setup_go_live_session(sensor_id=to_kill[host]["sensor_id"], host=to_kill[host]["host"],
                                              override_existing_session=True)
                if session.go_live_session_status:
                    for pid in to_kill[host]["die!"]:
                        pid_to_kill, cmdline, proc_name = pid
                        die = session.kill_process(pid=pid_to_kill)
                        if die:
                            if host not in killed_in_session:
                                killed_in_session[host] = []
                            killed_in_session[host].append(pid_to_kill)
                            logging.info("Proc with the PID {} ({}) was killed! (cmdline: {})."
                                         .format(pid_to_kill, proc_name, cmdline))
                        else:
                            if host not in killed_in_session:
                                killed_in_session[host] = []
                            killed_in_session[host].append(pid_to_kill)
                            logging.info("Proc with the PID {} ({}) is already dead! (cmdline: {})."
                                         .format(pid_to_kill, proc_name, cmdline))

                    session.close_session()
