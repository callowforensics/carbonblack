#!/usr/bin/env python3
from cb_framework import CbGoLive
import cb_logger
import sys
import os


if __name__ == "__main__":
    # Check that the user has enter enough args.
    if len(sys.argv) != 8:
        print("Usage: cb_api_key cb_server_url output_dir hosts_to_get_mft_from fget_location "
              "seven_zip_x86_path seven_zip_x64_path")
        print("\nExample:")
        print("-" * 50)
        print(r"abcdefghijklmnopqrstuvwxyz https://123.456.789.1 c:\output hosts_to_get_mft_from.txt"
              r" c:\fget.exe c:\7zip_x86 c:\7zip_x64")
        sys.exit()
        
    cb_api = sys.argv[1]
    cb_url = sys.argv[2]
    output_dir = sys.argv[3]
    hosts = sys.argv[4]
    fget_location = sys.argv[5]
    seven_zip_x86_path = sys.argv[6]
    seven_zip_x64_path = sys.argv[7]
    
    with open(hosts, "r") as f:
        hosts_to_get_from = [line.strip() for line in f if line != "\n"]
        
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    cb_logger.logger(output_dir)
    
    triage = CbGoLive(cb_api_key=cb_api, cb_server_url=cb_url, cb_output_path=output_dir)
    triage.get_sensor_details()
    online = triage.online_sensors
    
    for host_to_get in hosts_to_get_from:    
        for sensor in online:
            if sensor["computer_name"].lower() == host_to_get.lower():
                sensor_id, host, os_version = sensor["id"], sensor["computer_name"],\
                                              sensor["os_environment_display_string"]
                # Get the 7zip version.
                if "64-bit" in os_version:
                    zip_path = seven_zip_x64_path
                else:
                    zip_path = seven_zip_x86_path
        
                # Start the session.
                triage.setup_go_live_session(sensor_id=sensor_id, host=host)
                if triage.go_live_session_status:
                    # Get the files to put
                    files_to_put = []
                    for path, dirs, files in os.walk(zip_path):
                        for filename in files:
                            fullpath = os.path.join(path, filename)
                            files_to_put.append(fullpath)
        
                    # upload the 7zip files.
                    for file in files_to_put:
                        fullpath, filename = file
                        triage.put_file(file_to_put=fullpath, working_directory="c:\windows\carbonblack")
        
                    # Put FGET.exe
                    triage.put_file(file_to_put=fget_location, working_directory=r"c:\windows\carbonblack")
        
                    # Execute the commands to get the MFT.
                    triage.execute_command(command="c:\windows\carbonblack\FGET.exe -extract c:\$MFT "
                                                   "c:\windows\carbonblack\c_mft.bin")
        
                    # Add file to archive.
                    triage.execute_command(command=r"c:\windows\system32\cmd.exe /c c:\windows\carbonblack\7za.exe "
                                                   r"a -tzip mft.zip c_mft.bin")

                    # Get the archive.
                    triage.get_file(file=r"c:\windows\carbonblack\mft.zip")
        
                    # Delete the mft file.
                    triage.delete_file(file=r"c:\windows\carbonblack\c_mft.bin")

                    # Delete the fget file.
                    triage.delete_file(file=r"c:\windows\carbonblack\fget.exe")       
                       
                    # Delete the 7zip files.
                    for file in files_to_put:
                        fullpath, filename = file
                        triage.delete_file(file="c:\windows\carbonblack\{}".format(filename))
        
                    # Delete the archive.
                    triage.delete_file(file=r"c:\windows\carbonblack\mft.zip")
        
                    # Close the session.
                    triage.close_session()
