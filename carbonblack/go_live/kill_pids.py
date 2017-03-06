from cb_framework import CbGoLive
import cb_logger
import os
import sys


if __name__ == "__main__":
    # Check that the user has enter enough args.
    if len(sys.argv) != 6:
        print("Usage: cb_api_key cb_server_url output_dir host text_file_containing_pids")
        print("\nExample:")
        print("-" * 50)
        print(r"abcdefghijklmnopqrstuvwxyz https://123.456.789.1 c:\output testsys1 pids_to_kill.txt")
        sys.exit()

    cb_api = sys.argv[1]
    cb_url = sys.argv[2]
    output_dir = sys.argv[3]
    host = sys.argv[4]
    pids_file = sys.argv[5]

    with open(pids_file, "r") as f:
        pids_to_kill = [line.strip() for line in f if line != "\n"]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cb_logger.logger(output_dir)

    triage = CbGoLive(cb_api_key=cb_api, cb_server_url=cb_url, cb_output_path=output_dir)
    triage.get_sensor_details()
    online = triage.online_sensors

    for sensor in online:
        if sensor["computer_name"].lower() == host.lower():
            sensor_id, host = sensor["id"], sensor["computer_name"]
            triage.setup_go_live_session(sensor_id=sensor_id, host=host, override_existing_session=True)
            if triage.go_live_session_status:
                for pid in pids_to_kill:
                    triage.kill_process(pid=pids_file)
                triage.close_session()
