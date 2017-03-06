#!/usr/bin/env python3
from time import gmtime, strftime
import os
import sys
from cb_framework import CbProcess
import cb_logger

if __name__ == "__main__":
    # Check that the user has enter enough args.
    if len(sys.argv) != 5:
        print("Usage: cb_api_key cb_server_url output_dir process_id")
        print("\nExample:")
        print("-" * 50)
        print(r"abcdefghijklmnopqrstuvwxyz https://123.456.789.1 c:\output 00000482-0002-b7d0-01d2-77025a8901dc/1")
        sys.exit()

    cb_api = sys.argv[1]
    cb_url = sys.argv[2]
    output_dir = sys.argv[3]
    process_id = sys.argv[4]

    time_now = strftime("%Y-%m-%d %H:%M:%S", gmtime()).replace(" ", "_").replace(":", "-")
    output_dir = os.path.join(output_dir, time_now)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cb_logger.logger(output_dir)

    # You must pass the process_id within a list.
    process = CbProcess(cb_api_key=cb_api,
                        cb_server_url=cb_url,
                        cb_output_path=output_dir,
                        process_ids=[process_id])

    if process.process_data_store:
        process.create_process_report(processes=process.process_data_store)
