#!/usr/bin/env python3
import requests
import time
from time import gmtime, strftime
import logging
import datetime
import csv
import os
import sys
import ntpath
import netaddr
import platform

__author__ = "Andrew Callow"
__copyright__ = "Andrew Callow"
__title__ = "cb_framework.py"
__license__ = "Proprietary"
__version__ = "1.0"
__email__ = "acallow@btinternet.com"
__status__ = "Prototype"


class _CbConnect(object):
    """Manages HTTP requests to CB Server"""

    def __init__(self):
        self._cb_api_key = ""
        requests.packages.urllib3.disable_warnings()  # Disable insecure connection warnings.

    def _get_cb_json(self, cb_server_url=None, payload=None, return_json=True):
        """Issues "GET" command and returns decoded JSON object.
        Args:
            cb_server_url: URL to "GET".
            payload: The HTTP payload.
            return_json: By default, JSON is returned, however if set to "False", the raw content is returned.
        Returns:
            JSON/Raw Content/None object (None object if status code is not 200).
        """
        # Get the JSON from CB server.
        try:
            get_data = requests.get(cb_server_url,
                                    headers={"X-Auth-Token": self._cb_api_key},
                                    params=payload,
                                    verify=False)
            # Handle return.
            _http_response_code = get_data.status_code
            if _http_response_code == 200:
                if not return_json:
                    return get_data.content
                else:
                    return get_data.json()
        except requests.exceptions.ConnectionError:
            return None

    def _post_cb_json(self, cb_server_url=None, payload=None, files=None):
        """Issues "POST" command and returns decoded JSON object.
        Args:
            cb_server_url: URL to "POST".
            payload: JSON payload (if passed to method)
            files: Dictionary containing file object for "put" methods (if passed to method).
        Returns:
            HTTP status code and/or decoded JSON/None object.
        """
        # Get the JSON from CB server.
        try:
            post_data = requests.post(cb_server_url,
                                      json=payload,
                                      files=files,
                                      headers={"X-Auth-Token": self._cb_api_key},
                                      verify=False)
            # Handle return.
            _http_response_code = post_data.status_code
            if _http_response_code == 200:
                return post_data.json()
        except requests.exceptions.ConnectionError:
            return None

    def _put_cb_json(self, cb_server_url=None, payload=None):
        """Issues "PUT" command and returns decoded JSON object.
        Args:
            cb_server_url: URL to "PUT".
            payload: JSON payload.
        Returns:
            HTTP status code and/or decoded JSON/None object..
        """
        # Get the JSON from CB server.
        try:
            put_data = requests.put(cb_server_url,
                                    json=payload,
                                    headers={"X-Auth-Token": self._cb_api_key},
                                    verify=False)
            # Handle return.
            _http_response_code = put_data.status_code
            if _http_response_code == 200:
                return put_data.json()
        except requests.exceptions.ConnectionError:
            return None


class CbKeepAlive(_CbConnect):
    """Keeps a go live session alive"""

    def __init__(self, cb_server_url=None, session_id=None):
        """
         Args:
            cb_server_url: CB server URL.
            session_id: Session ID to keep alive.
        """
        super().__init__()
        # Check if the supplied URL needs the trailing "/" removing.
        if cb_server_url[-1] == "/":
            cb_server_url = cb_server_url[:-1]
        # Path to relevant API.
        session_api_path = cb_server_url + "/api/v1/cblr/session"
        while True:
            time.sleep(60)
            try:
                alive = self._get_cb_json(session_api_path + "/{}/keepalive".format(session_id))
                if alive:
                    logging.debug("Sent keep alive request for the session: {}.".format(session_id))
            except requests.exceptions.ConnectionError:
                pass


# noinspection PyTypeChecker
class CbGoLive(_CbConnect):
    def __init__(self, cb_api_key=None, cb_server_url=None, cb_output_path=None):
        """Class for all CB GoLive operations.
       Args:
            cb_api_key: CB API key.
            cb_server_url: CB server URL.
            cb_output_path: Output directory.
       Attributes:
           self.cb_api_key: CB API key.
           self.cb_server_url: CB server URL.
           self.sensor_api_path: Path to sensor CB API.
           self.session_api_path: Path to session API.
           self.output_path: Main output directory.
           self.host_path: Output directory for the specific host.
           self.online_sensors: List to store details of online sensors.
           self.offline_sensors: List to store details of online sensors.
           self.go_live_session_status: Stores the status of the go live session connection.
           self._session_id: Stores the session id needed to perform go live operations.
           self._command_id: Stores the command id needed to perform go live operations.
           self._host: Stores the active session's host name.
           self._sensor_id: Stores the active session's sensor id.
           self.host_drives_list: Stores the available drive letters for the attached host.
       """
        # Call to superclass.
        super().__init__()
        self._cb_api_key = cb_api_key
        self._cb_server_url = cb_server_url
        self.output_path = cb_output_path
        self.host_output_path = None
        self.online_sensors = []
        self.offline_sensors = []
        self.go_live_session_status = None
        self.session_id = None
        self._command_id = None
        self._host = None
        self._sensor_id = None
        self.host_drives_list = None

        # Check if the supplied URL needs the trailing "/" removing.
        if self._cb_server_url[-1] == "/":
            self._cb_server_url = self._cb_server_url[:-1]

        self._sensor_api_path = self._cb_server_url + "/api/v1/sensor"
        self._session_api_path = self._cb_server_url + "/api/v1/cblr/session"

    def get_sensor_details(self):
        """Gets details of online/offline sensors"""
        # Output/logging.
        logging.info("Attempting to get sensor information from CB server ({}).".format(self._cb_server_url))
        # Get an instance of the CBConnect class, which returns the decoded JSON (list of dictionaries).
        sensor_list = self._get_cb_json(self._sensor_api_path)

        # Check if we have a successful result.
        if sensor_list:
            # Output/logging.
            logging.info("Obtained sensor information from CB Server.")
        else:
            # Output/logging.
            logging.error("Failed to get the sensor information from CB Server.")
            # Quit as if we can't get the sensor info we cannot do anything.
            sys.exit()

        # Loop through the list of dictionaries and get the online and offline sensors.
        for sensor_data in sensor_list:
            if sensor_data["status"] == "Online":
                self.online_sensors.append(sensor_data)
            else:
                self.offline_sensors.append(sensor_data)

        # Output/logging.
        logging.info("Sorted list of online/offline sensors.")
        return

    def setup_go_live_session(self, sensor_id=None, host=None, override_existing_session=False,
                              create_unique_directory_for_host=False):
        """Sets up a go live session
        Args:
            sensor_id: the host:'s sensor id.
            host: the host: name.
            override_existing_session: Flag to kill already existing sessions so new ones can be created.
            create_unique_directory_for_host: Determines whether a unique directory should be created to store host
            data.
        """
        # Set a connection attempt counter
        connection_attempts = 0
        while True:
            # Ensure the session status is initially set to None.
            self.go_live_session_status = None
            # Set the host.
            self._host = host
            # Set the sensor id.
            self._sensor_id = sensor_id
            # Set the payload.
            payload = {"sensor_id": int(self._sensor_id)}
            # Output/logging.
            logging.info("Attempting to start session for the host: {} (sensor_id: {})."
                         .format(self._host, self._sensor_id))
            # Create a new Go Live session.
            new_session = self._post_cb_json(self._session_api_path, payload=payload)

            # Check if we have a successful result.
            if new_session:
                # Output/logging.
                logging.debug("successfully initiated new Go Live session for the host: {} "
                              "(waiting for \"active\" session status).".format(self._host))
                break
            else:
                # Kill existing session.
                if override_existing_session and connection_attempts != 1:
                    # Get all sessions.
                    get_sessions = self._get_cb_json(self._session_api_path)
                    if get_sessions:
                        # Find the session we want.
                        for session in get_sessions:
                            if session["hostname"].lower() == self._host.lower():
                                if session["status"] == "active" or session["status"] == "pending":
                                    # Set the session ID.
                                    self.session_id = str(session["id"])
                                    # Close the existing session.
                                    self.close_session()
                                    logging.info("Killed existing Go Live session for the host: {} ("
                                                 "sleeping for 10 seconds until next connection attempt)."
                                                 .format(self._host))
                                    time.sleep(10)
                    # Increment the connection_attempts counter.
                    connection_attempts += 1
                    continue
                else:
                    logging.error("Unable to initiate new Go Live session for the host: {}.".format(self._host))
                    self.go_live_session_status = None
                    return

        # Set the session id.
        self.session_id = str(new_session["id"])
        # Setup a counter.
        session_setup_attempts = 0
        # Loop to get the results.
        while session_setup_attempts < 15:
            check_session_status = self._get_cb_json(self._session_api_path + "/{}".format(self.session_id))
            # Increment the counter.
            session_setup_attempts += 1
            # Check if we have a successful result.
            if check_session_status:
                if check_session_status["status"] != "active":
                    # Output/logging.
                    logging.debug("Sensor ID: {} ({}) reports: \"{}\" after {} attempt(s)."
                                  .format(self._sensor_id, self._host, check_session_status["status"],
                                          session_setup_attempts))
                    # Sleep for 5 seconds.
                    time.sleep(5)
                    continue
                # Return to the main program if is we have an active session.
                else:
                    # Output/logging.
                    logging.info("Session for the host: {} is now active.".format(self._host))
                    # Update the session status.
                    self.go_live_session_status = True
                    # Store the array of drive letters.
                    self.host_drives_list = check_session_status["drives"]
                    # Create an output dir for the host's go_live data.
                    if create_unique_directory_for_host:
                        time_now = strftime("%Y-%m-%d %H:%M:%S", gmtime()).replace(" ", "_").replace(":", "-")
                        self.host_output_path = os.path.join(self.output_path, self._host, time_now)
                        try:
                            os.makedirs(self.host_output_path)
                        except FileExistsError:
                            pass
                        return
                    else:
                        self.host_output_path = os.path.join(self.output_path, self._host)
                        try:
                            os.makedirs(self.host_output_path)
                        except FileExistsError:
                            pass
                        return

            # Close session if we have a failure.
            else:
                self.close_session()
                return

        # Output/logging.
        logging.error("Session for the system {} could not be established.".format(self._host))
        # Update the session status.
        self.go_live_session_status = None
        # Close the session if is still pending after 15 attempts.
        self.close_session()
        return

    def _handle_commands(self, payload=None, command_type=None, return_key=None, limit_attempts=False):
        """Issues command to the go live session.
        Args:
            payload: JSON payload with command.
            return_key: The key for the required object.
            command_type: The type of command being issued.
            limit_attempts: Timeout flag for pending requests.
        Returns:
            Object with command results.
        """
        # Output/logging.
        logging.debug("Posting the command \"{}\" to the host: {}.".format(command_type, self._host))
        # Post the command.
        posted_command = self._post_cb_json(self._session_api_path + "/{}/command".format(self.session_id),
                                            payload=payload)

        # Check if we have a successful result.
        if posted_command:
            # Output/logging.
            logging.debug("\"{}\" command was successfully posted to the host: {}.".format(command_type, self._host))
        else:
            # Output/logging.
            logging.error("Failed to post the \"{}\" command to the host: {}.".format(command_type, self._host))
            return

        # Get the command id.
        self._command_id = posted_command["id"]

        # Loop to get the results.
        command_attempts = 0
        # Set an alive check value for hosts.
        host_alive_check_value = 15
        while True:
            command_result = self._get_cb_json(self._session_api_path + "/{}/command/{}"
                                               .format(self.session_id, self._command_id))
            # Check if we have a successful result and deal with the responses..
            if command_result:
                # Increment command attempts.
                command_attempts += 1

                # Handle error status.
                if command_result["status"] == "error":
                    logging.error("Error in \"{}\" command for the host: {}.".format(command_type, self._host))
                    return None

                # Handle complete status.
                if command_result["status"] == "complete":
                    if return_key:
                        return command_result[return_key]
                    else:
                        return "success"

                # Handle pending status.
                if command_result["status"] == "pending":
                    # Handle if system is still online if we have made 15 attempts to get the result of the command.
                    if command_attempts == host_alive_check_value:
                        check_host_status = self._get_cb_json(self._session_api_path + "/{}".format(self.session_id))
                        if check_host_status["status"] != "active":
                            logging.error("Error in \"{}\" command for the host: {} (host is now offline)."
                                          .format(command_type, self._host))
                            return None
                        else:
                            # Increment the host_alive_check value.
                            host_alive_check_value += 15

                # Handle the commands if the limit_attempts option is set.
                if limit_attempts and command_attempts == 15:
                    logging.error("Error in \"{}\" command for the host: {} (command timeout)."
                                  .format(command_type, self._host))
                    return None

            # Handle commands that just fail. at the post stage.
            else:
                logging.error("Error in \"{}\" command for the host: {}.".format(command_type, self._host))
                return None

    def close_session(self):
        """Closes go live session."""
        payload = {"id": self.session_id, "status": "close"}
        # Output/logging.
        logging.debug("Session closure request sent to CB Server for the host: {}.".format(self._host))
        # Close the session.
        close_session = self._put_cb_json(self._session_api_path + "/{}".format(self.session_id), payload)
        # Check if we have a successful result.
        if close_session:
            # Output/logging.
            logging.info("Session closed for the host: {}.".format(self._host))
            return
        else:
            logging.error("Session for the host: {} could not be closed.".format(self._host))
            return

    @staticmethod
    def _convert_unix_time(unix_time):
        """Decodes UNIX time stamps to human readable ones.
        Args:
            unix_time: UNIX time integer.
        Returns:
            Human readable date/time string.
        """
        try:
            return datetime.datetime.fromtimestamp(unix_time).strftime('%d-%m-%Y %H:%M:%S')
        # Return "unknown" if the conversion fails.
        except OSError:
            return "unknown"

    @staticmethod
    def _fix_path(path_to_fix=None, is_nt_path=True):
        """Decodes UNIX time stamps to human readable ones.
        Args:
            path_to_fix: Path to fix!
            is_nt_path: Set as true by default (as most paths will be windows paths.
        Returns:
            Fixed path or original path.
        """
        if is_nt_path:
            if not path_to_fix.endswith("\\*"):
                path_to_fix += "\\*"
                return path_to_fix
            else:
                return path_to_fix
        else:
            return path_to_fix

    def _stat(self, object_to_stat=None, return_file_details=False):
        """Checks if a file exists.
        Args:
           object_to_stat: file to check existence of.
           return_file_details: Return file details.
            is_nt_path: Set as true by default (as most paths will be windows paths.
        Returns:
            Bool indicating success.
        """
        # Get the path to be checked and the file name.
        file_path, file_to_check = ntpath.split(object_to_stat)[0], ntpath.split(object_to_stat)[1]
        # Check if the path needs fixing (must end with \*).
        directory = self._fix_path(path_to_fix=file_path)
        # Set the payload.
        payload = {"session_id": self.session_id,
                   "name": "directory list",
                   "object": directory}
        # Post the command.
        dir_list = self._handle_commands(payload=payload, command_type="directory list", return_key="files")
        # Check if we have a successful result.
        if dir_list:
            for entry in dir_list:
                if entry["filename"].lower() == file_to_check.lower():
                    if return_file_details:
                        return entry
                    else:
                        return True

        # Return none if file not found.
        return None

    def delete_file(self, file=None):
        """Deletes a file onto a host.
        Args:
           file: File to delete (pass a full path as string).
        """
        # Check fif the file exists.
        check_if_file_exists = self._stat(object_to_stat=file)
        # If does delete it:
        if check_if_file_exists:
            # Set the payload to actually delete the file from session storage to system storage.
            payload = {"session_id": self.session_id,
                       "name": "delete file",
                       "object": file}
            # Output/logging.
            logging.info("Attempting to delete the file \"{}\" from the host: {}.".format(file, self._host))
            # Execute the "delete file" command.
            delete_file_on_system = self._handle_commands(payload=payload, command_type="delete file")
            # Check if we have a successful result.
            if delete_file_on_system:
                # Now double check this by checking if the file is actually there.
                check_if_file_exists = self._stat(object_to_stat=file)
                # Check if we have a successful delete.
                if not check_if_file_exists:
                    logging.info("File \"{}\" deleted from the host: {}.".format(file, self._host))
                    return True
                else:
                    logging.info("Failed to delete the file \"{}\" from the host: {}.".format(file, self._host))
                    return None
            else:
                logging.info("Failed to delete the file \"{}\" from the host: {}.".format(file, self._host))
                return None
        else:
            logging.info("The file \"{}\" does not exist on the host: {}, so it can't be deleted."
                         .format(file, self._host))
            return None

    def execute_command(self, command=None, output_file=None, wait=True, working_directory=None):
        """Executes arbitrary commands.
        Args:
           command: Command to execute"
           output_file: File to store command results.
           wait: Tells the CB server to not report result until process has completed.
           working_directory: Optional working directory for process execution.
        """
        # create the payload.
        payload = {"session_id": self.session_id,
                   "name": "create process",
                   "object": command,
                   "wait": wait,
                   "working_directory": working_directory,
                   "output_file": output_file}

        # Execute the command.
        execute_command = self._handle_commands(payload=payload, command_type="execute")

        # Check if we have a successful result.
        if execute_command:
            logging.info("Executed the command \"{}\" on the host: {}.".format(command, self._host))
            return True
        else:
            logging.info("Failed to execute the command \"{}\" on the host: {}."
                         .format(command, self._host))
            return None

    def get_directory_listing(self, directories=None):
        """Gets directory listing from a host.
        Args:
           directories: List of paths for which the directory listing should be returned.
        Returns:
            List of dictionaries containing directory listings.
        """
        # Check if a list has been passed.
        if type(directories) != list:
            raise TypeError("\"directories\" variable requires type list, got {}.".format(type(directories)))

        # Create a list to store teh directories.
        directory_list_results = []

        # Loop through the directories to get the listings for.
        for directory in directories:
            # Store a copy of the directory name for stdout.
            directory_stdout = directory
            # Check if the path needs fixing (must end with \*).
            directory = self._fix_path(path_to_fix=directory)

            # Set the payload.
            payload = {"session_id": self.session_id,
                       "name": "directory list",
                       "object": directory}
            # Post the command.
            dir_list = self._handle_commands(payload=payload, command_type="directory list", return_key="files")

            # Check if we have a successful result.
            if dir_list:
                logging.info("Got directory listing from the host: {} (for \"{}\")."
                             .format(self._host, directory_stdout))
                directory_list_results.append({"directory": directory_stdout, "results": dir_list})
            else:
                logging.info("Failed to get directory listing from the host: {} (for \"{}\")."
                             .format(self._host, directory_stdout))
                continue

        # Return the directory listings.
        return directory_list_results

    def get_file(self, file=None):
        """Gets file from a host.
        Args:
           file: file name (full path) to get (pas as a string).
        """

        # Handle where we want the file to be renamed.
        if "||" in file:
            renamed_file = file.split("||")[1]
            file = file.split("||")[0]
        else:
            renamed_file = None

        # Check if the file exists.
        check_if_file_exists = self._stat(object_to_stat=file, return_file_details=True)

        # Check if we have a successful result.
        if check_if_file_exists:
            # Output/Logging.
            logging.info("File existence check for \"{}\" on the host: {} was successful (file size: {:,} bytes)"
                         ". Carbon Black is now uploading the file to its staging area before local download can"
                         " commence.".format(file, self._host, check_if_file_exists["size"]))
            #  Set the payload.
            payload = {"session_id": self.session_id,
                       "name": "get file",
                       "object": file,
                       "offset": 0,
                       "get_count": None}

            # Post the command, which gets the "file_id" of the file we want.
            file_id = self._handle_commands(payload=payload, command_type="get file", return_key="file_id")

            # Check if we have a successful result.
            if file_id:
                url = "{}/{}/file/{}/content".format(self._session_api_path, self.session_id, file_id)
                # get the file.
                try:
                    get_file = requests.get(url,
                                            headers={"X-Auth-Token": self._cb_api_key},
                                            stream=True,
                                            verify=False)
                    # Do this if we have a result.
                    if get_file:
                        logging.info("Carbon Black has finished uploading the file {0} to its staging area. "
                                     "Now downloading the file \"{0}\" (host: {1}) to the specified output directory."
                                     .format(file, self._host))
                        # Open a binary file.
                        if renamed_file:
                            out_file = os.path.join(self.host_output_path, "{}_{}"
                                                    .format(self._host, renamed_file))
                        else:
                            out_file = os.path.join(self.host_output_path, "{}_{}"
                                                    .format(self._host, file.split("\\")[-1]))

                        with open(out_file, "wb") as f:
                            # Write the data in chunks.
                            for chunk in get_file.iter_content(chunk_size=1024):
                                if chunk:
                                    f.write(chunk)

                        # Output/logging.
                        logging.info("Got the file \"{}\" from the host: {}.".format(file, self._host))
                        return True
                    else:
                        logging.info("Failed to get the file \"{}\" from the host: {}.".format(file, self._host))
                        return None
                except requests.exceptions.ConnectionError:
                    logging.info("Failed to get the file \"{}\" from the host: {}.".format(file, self._host))

        else:
            logging.warning("File existence check for \"{}\" on the host: {} failed.".format(file, self._host))
            return None

    def get_running_processes(self):
        """Gets running processes from a host.
        Returns:
            List of running processes for a host.
        """
        # Set the payload.
        payload = {"session_id": self.session_id,
                   "name": "process list"}
        # Post the command.
        process_list = self._handle_commands(payload=payload, command_type="process list", return_key="processes")

        # Check if we have a successful result.
        if process_list:
            logging.info("Got process list from the host: {}.".format(self._host))
            # Close the session if requested to do so.
            return process_list
        else:
            logging.info("Failed to get process list from the host: {}.".format(self._host))
            return None

    def kill_process(self, pid=None):
        """Kills a processes on host.
        Args:
           pid: process to kill.
        """
        # Check if a list has been passed.
        proc_list = self.get_running_processes()

        # Check if the PID does not exist by looping through all pids.
        if not any(str(process["pid"]) == str(pid) for process in proc_list):
            logging.info("PID {} does not exist on the host: {}.".format(pid, self._host))
            return None

        # Set the payload.
        payload = {"session_id": self.session_id,
                   "name": "kill",
                   "object": pid}

        # Post the command.
        kill_pid = self._handle_commands(payload=payload, command_type="kill process")

        # Check if we have a successful result.
        if kill_pid:
            logging.info("Killed PID {} on the host: {}.".format(pid, self._host))
            return True
        else:
            logging.info("Failed to kill PID {} on the host: {}.".format(pid, self._host))
            return None

    def mem_dump(self, remote_path=None, compress=True):
        """Gets a mem dump.
        Args:
           remote_path: Path for which memory dump should be stored.
           compress: Determines whether compression should be used.
        """
        # Set the payload.
        payload = {"session_id": self.session_id,
                   "name": "memdump",
                   "object": remote_path,
                   "compress": compress}

        # Post the command.
        get_memdump = self._handle_commands(payload=payload, command_type="memdump")

        # Set the extension of memdump file to collect as .zip if compression was used.
        if compress:
            remote_path += ".zip"

        # Check if we have a successful result.
        if get_memdump:
            logging.info("Memdump completed for the host: {}.".format(self._host))
            self.get_file(file=remote_path)
        else:
            logging.info("Memdump failed for the host: {}.".format(self._host))

    def put_file(self, working_directory=None, file_to_put=None, create_remote_path=True):
        """puts a file onto a host.
        Args:
           working_directory: The absolute path of where the files are going WITHOUT the filename.
           file_to_put: Filename (full path) of the local file to put.
           create_remote_path: Determines whether to create a remote path (if it does not exist).
        """

        # Output/logging.
        logging.info("Checking if the target directory, \"{}\", exists on the host: {}."
                     .format(working_directory, self._host))

        # We assume we are "putting" to a win box.
        remote_file = ntpath.join(working_directory, ntpath.split(file_to_put)[1])

        # Check if the folder exists on the host.
        check_remote_path = self._stat(object_to_stat=working_directory)

        # If it does not exist, create it.
        if not check_remote_path:
            if create_remote_path:
                # Output/logging.
                logging.info("The target directory, \"{}\", did not exist on the host {}, so it will be created."
                             .format(working_directory, self._host))
                create_dir = self.execute_command({"command": r"c:\windows\system32\cmd.exe /c mkdir {}"
                                                  .format(working_directory, self._host)})
                if not create_dir:
                    logging.info("The target directory, \"{}\", could not be created on the host {}."
                                 .format(working_directory, self._host))
                    return None
            else:
                logging.info("As requested, the target directory, \"{}\",will not be created on the host: {}, "
                             "and the put operation for the file {} wil be skipped."
                             .format(working_directory, self._host, file_to_put))
                return None

        # Output/logging.
        logging.info("The target directory, \"{}\", does exist on the host: {}."
                     .format(working_directory, self._host))

        file_to_put_name = file_to_put
        # Open the file to be "put".
        file_to_put = open(file_to_put, "rb")
        # set the URL that needs to be posted to in order to upload the file to the session.
        url = "{}/{}/file".format(self._session_api_path, self.session_id)
        # Set a payload that contains the file for posting.
        files_to_post = {"file": file_to_put}
        # Do the POST request.
        post_file_to_session = self._post_cb_json(url, files=files_to_post)

        # Check if we have a successful result.
        if post_file_to_session:
            # Get the file_id of the fil in session storage.
            file_id = post_file_to_session['id']
            # Set the payload to actually put the file from session storage to system storage.
            payload = {"session_id": self.session_id,
                       "name": "put file",
                       "object": remote_file,
                       "file_id": file_id}
            # Output/logging.
            logging.info("Attempting to put the file \"{}\" onto the host: {}.".format(file_to_put_name, self._host))
            # Execute the "put file" command.
            put_file_on_system = self._handle_commands(payload=payload, command_type="put file")

            # Check if we have a successful result.
            if put_file_on_system:
                # Now double check this bt checking if the file is actually there.
                check_if_file_exists = self._stat(object_to_stat=remote_file)

                # Check if we have a successful result.
                if check_if_file_exists:
                    logging.info("Put the file \"{}\" as \"{}\" on the host: {}."
                                 .format(file_to_put_name, remote_file, self._host))
                    return True
                else:
                    logging.info("Failed to put the file \"{}\" onto the host: {}."
                                 .format(file_to_put_name, self._host))
                    return None
            else:
                logging.info("Failed to put the file \"{}\" onto the host: {}.".format(file_to_put_name, self._host))
                return None
        else:
            logging.info("Failed to put the file \"{}\" onto the host: {}, as the folder \"{}\" does not exist."
                         .format(file_to_put_name, self._host, remote_file))
            return None

    def reg_enum_key(self, keys=None):
        """Enumerates Registry Keys.
        Args:
           keys: List of keys.
        Returns:
            List of dictionaries containing Registry Key details.
        """
        # Check if a list has been passed
        if type(keys) != list:
            raise TypeError("\"keys\" variable requires type list, got {}.".format(type(keys)))

        # Create a list to store the directories.
        key_results = []

        # Loop through the keys that require enumerating.
        for key in keys:
            # Set the payload.
            payload = {"session_id": self.session_id,
                       "name": "reg enum key",
                       "object": key}
            # Post the command.
            reg_keys = self._handle_commands(payload=payload, command_type="reg key enumeration", return_key="sub_keys")

            # Check if we have a successful result.
            if reg_keys:
                logging.info("Reg enum for \"{}\" on the host: {} successful.".format(key, self._host))
                key_results.append({"key": key, "sub_keys": reg_keys})
            else:
                logging.info("Reg enum for \"{}\" on the host: {} unsuccessful.".format(key, self._host))
                continue

        # Return the results.
        return key_results

    def reg_query_value(self, values=None):
        """Queries a registry value.
        Args:
           values: List of reg values.
        """
        # Check if a list has been passed.
        if type(values) != list:
            raise TypeError("\"values\" variable requires type list, got {}.".format(type(values)))
        # Create a list to store the directories.
        value_results = []

        # Loop through the values that require querying.
        for value in values:
            # Set the payload.
            payload = {"session_id": self.session_id,
                       "name": "reg query value",
                       "object": value}
            # Post the command.
            reg_values = self._handle_commands(payload=payload, command_type="reg value query", return_key="value")
            # Check if we have a successful result.
            if reg_values:
                logging.info("Got reg value from the host: {} (for \"{}\").".format(self._host, value))
                value_results.append({"value": value, "results": reg_values})
            else:
                logging.info("Failed to get reg value from the host: {} (for \"{}\").".format(self._host, value))
                continue

        return value_results

    def reg_delete_key(self, keys=None):
        """Deletes a registry key.
        Args:
           keys: List of keys to delete.
        """
        # Check if a list has been passed.
        if type(keys) != list:
            raise TypeError("\"keys\" variable requires type list, got {}.".format(type(keys)))

        # Loop through the values that require deleting.
        for key in keys:
            # Set the payload.
            payload = {"session_id": self.session_id,
                       "name": "reg delete key",
                       "object": key}
            # Post the command.
            delete_key = self._handle_commands(payload=payload, command_type="delete reg key")
            # Check if we have a successful result.
            if delete_key:
                logging.info("Reg key \"{}\" deleted on the host: {}.".format(key, self._host))
            else:
                logging.info("Reg key \"{}\" was not deleted on the host: {}.".format(key, self._host))
                continue

    def reg_delete_value(self, values=None):
        """Deletes a registry value.
        Args:
           values: List of keys to create.
        """
        # Check if a list has been passed.
        if type(values) != list:
            raise TypeError("\"values\" variable requires type list, got {}.".format(type(values)))

        # Loop through the values that require deleting.
        for value in values:
            # Set the payload.
            payload = {"session_id": self.session_id,
                       "name": "reg delete value",
                       "object": value}
            # Post the command.
            delete_value = self._handle_commands(payload=payload, command_type="delete reg value")
            # Check if we have a successful result.
            if delete_value:
                logging.info("Reg value \"{}\" deleted on the host: {}.".format(value, self._host))
            else:
                logging.info("Reg value \"{}\" was not deleted on the host: {}.".format(value, self._host))
                continue

    def reg_set_value(self, values=None, overwrite=False):
        """Sets registry values
        Args:
            values: A list of dictionaries.
            overwrite: Determines whether a reg value should be replaced (default is false).
            executes.
        """
        # Check if a list has been passed.
        if type(values) != list:
            raise TypeError("\"values\" variable requires type list, got {}.".format(type(values)))

        # Loop through the values that require setting.
        for value in values:
            # Throw exception if list object is not type dict.
            if type(value) != dict:
                raise TypeError("Non dict element passed in \"values\" list (got type {}.".format(type(value)))
            # Handle REG_BINARY type.
            if value["value_type"].upper() == "REG_BINARY" and type(value["value_date"]) != bytes:
                raise TypeError("Value passed as reg type \"{}\" is not of type: \"bytes\" "
                                "(got {})".format(value["value_type"], type(value["value_data"])))
            # Handle REG_DWORD and REG_QWORD type.
            elif value["value_type"].upper() == "REG_DWORD" or value["value_type"].upper() == "REG_QWORD" \
                    and type(value["value_data"]) != int:
                value["value_data"] = int(value["value_data"])
            # Handle REG_SZ type.
            elif value["value_type"].upper() == "REG_SZ" and type(value["value_data"]) != str:
                raise TypeError("Value passed as reg type \"{}\" is not of type: \"bytes\" "
                                "(got {})".format(value["value_type"], type(value["value_data"])))
            # Handle REG_MULTI_SZ.
            elif value["value_type"].upper() == "REG_MULTI_SZ" and type(value["value_data"]) != list:
                raise TypeError("Value passed as reg type \"{}\" is not of type: \"list\" "
                                "(got {})".format(value["value_type"], type(value["value_data"])))

            # Set the payload.
            payload = {"session_id": self.session_id,
                       "name": "reg set value",
                       "object": value["value_path"],
                       "value_data": value["value_data"],
                       "value_type": value["value_type"].upper(),
                       "overwrite": overwrite}
            # Post the command.
            set_value = self._handle_commands(payload=payload, command_type="reg set value")
            # Check if we have a successful result.
            if set_value:
                logging.info("Reg value \"{}\" set on the host: {}.".format(str(value["value_data"]), self._host))
            else:
                logging.info("Reg value \"{}\" was not set on the host: {}."
                             .format(str(value["value_data"]), self._host))
                continue

    def create_directory_listing_report(self, directories=None):
        """Gets directory listing from a host.
        Args:
            directories: The directory listing object (list of dictionaries).
        """
        # Check if a list has been passed.
        if type(directories) != list:
            raise TypeError("\"dir_listings\" variable requires type list, got {}.".format(type(directories)))
        # List to store the directory/file entries.
        dir_list = []

        # Loop through each dict within the list.
        for directory in directories:
            # Skip if length of the inner dict["results"] is 2 (these are just the dot double-dot entries.
            if len(directory["results"]) == 2:
                logging.info("There are no files/folders present within \"{}\"".format(directory["directory"]))
                continue
            else:
                # Iterate over each dict in the "results" key.
                for record in directory["results"]:
                    # Skip the dot-double dot.
                    if record["filename"] == "." or record["filename"] == "..":
                        continue
                    # Determine whether we have a file or directory.
                    if "DIRECTORY" in record["attributes"]:
                        entry_type = "directory"
                    else:
                        entry_type = "file"
                    # Get the attributes and join them as a pipe-delimited string.
                    attributes = ""
                    for index, attribute in enumerate(record["attributes"], start=1):
                        if index != len(record["attributes"]):
                            attributes += attribute + "|"
                        else:
                            attributes += attribute
                    # Join the root path to the returned paths.
                    if len(directory["directory"]) == 3 and directory["directory"][0].isalpha():
                        full_path = directory["directory"] + record["filename"]
                    else:
                        full_path = directory["directory"] + "\\" + record["filename"]
                    # Add the directory/file listing to dir_list as a list of items.
                    dir_list.append([record["create_time"],
                                     self._convert_unix_time(record["create_time"]),
                                     self._convert_unix_time(record["last_access_time"]),
                                     self._convert_unix_time(record["last_write_time"]),
                                     entry_type,
                                     full_path,
                                     str(record["size"]),
                                     attributes])

        # Write the directory/file listings to CSV.
        try:
            with open(os.path.join(self.host_output_path, "{}_directory_listing.csv".format(self._host)),
                      "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Create Time", "Last Access Time", "Last Write Time", "Type", "File/Folder Name",
                                 "Size", "attributes"])
                for entry in sorted(dir_list):
                    # Ignore first item in list (used for sorting only).
                    writer.writerow(entry[1:])
                return
        except PermissionError:
            logging.error("Report could not be written (likely because it is already open).")

    def create_running_process_report(self, process_list=None):
        """Gets directory listing from a host.
        Args:
            process_list: The process list object.
        """
        # List to store the process listing.
        proc_list = []

        # Loop through the process listings.
        for entry in process_list:
            # Handle instances whereby the create_time value is before the year 1900.
            try:
                create_time = self._convert_unix_time(entry["create_time"])
            except ValueError:
                create_time = "Date returned is < 1900"

            # Add the process listing to proc_list as a list of items.
            proc_list.append([create_time,
                              entry["path"],
                              str(entry["pid"]),
                              str(entry["parent"]),
                              entry["command_line"],
                              entry["username"],
                              entry["sid"],
                              entry["proc_guid"],
                              entry["parent_guid"]])

        # Write the process list to CSV.
        try:
            with open(os.path.join(self.host_output_path, "{}_process_listing.csv".format(self._host)),
                      "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Create Time", "Path", "PID", "Parent PID", "Command Line", "Username",
                                 "SID", "Process GUID", "Parent GUID"])
                for row in sorted(proc_list):
                    writer.writerow(row)
                return
        except PermissionError:
            logging.error("Report could not be written (likely because it is already open).")

    def create_reg_enum_report(self, sub_keys=None):
        """Creates reg key enum reports.
        Args:
            sub_keys: List of dicts containing results..
        """
        # Check if a list has been passed.
        if type(sub_keys) != list:
            raise TypeError("\"sub_keys\" variable requires type list, got {}.".format(type(sub_keys)))

        # List to store the sub-keys.
        keys = []

        # Loop through the directory/file listings.
        for result in sub_keys:
            for sub_key in result["sub_keys"]:
                # Join the root key to the sub-key and append the full registry path to keys as a list.
                key = result["key"] + "\\" + sub_key
                keys.append([key])

        # Write the keys to CSV.
        try:
            with open(os.path.join(self.host_output_path, "{}_reg_enum.csv".format(self._host)), "w", newline="",
                      encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Key Name"])
                for row in sorted(keys):
                    writer.writerow(row)
                return
        except PermissionError:
            logging.error("Report could not be written (likely because it is already open).")

    def create_reg_value_report(self, values):
        """Creates reg value reports.
        Args:
            values: dict of reg values.
        """
        # Check if a list has been passed.
        if type(values) != list:
            raise TypeError("\"values\" variable requires type list, got {}.".format(type(values)))

        # Create a list to store the results.
        reg_values = []

        # Create a list of the value to be written.
        for value in values:
            reg_values.append([value["value"], str(value["results"]["value_data"]), value["results"]["value_type"]])
        # Write the values to CSV.
        try:
            with open(os.path.join(self.host_output_path, "{}_reg_values.csv".format(self._host)), "a", newline="",
                      encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Key Name", "Value", "Value Type"])
                for row in reg_values:
                    writer.writerow(row)
                return
        except PermissionError:
            logging.error("Report could not be written (likely because it is already open).")


class CbProcess(_CbConnect):
    """Handles process queries.
    Algorithm is as follows:
        If process has not been previously processed, the processes' full data is stored and processed recursively
        (unless a proc is whitelisted) or is before the max recursion date. If the proc has already been seen,
        only new child procs are parsed (e.g an open Explorer session whereby new evil has been spawned etc.
    """

    def __init__(self, process_ids=None, cb_api_key=None, cb_server_url=None, cb_output_path=None,
                 completed_procs=None):
        """Class for all CB process operations.
           Args:
                cb_api_key: CB API key.
                cb_server_url: CB server URL.
                cb_output_path: Output directory.
                completed_procs: Already processed procs.
           Attributes:
               self._cb_api_key: CB API key.
               self._cb_server_url: CB server URL.
               self.output_path: Output directory.
               self._process_api_path: Path to sensor CB API.
               self._process_ids: The Top level process ID passed when instantiating class.
               self._alert_process_segments: List that contains the alert being parsed, plus all its parents/children.
               self._completed_process_segments: All completed process segment IDs.
               self._process_data_store: All downloaded proc data.
               self._process_data: The process data of the process currently being parsed.
               self._process_id: The process id of the process currently being parsed.
               self._process_name: The name of the process that is currently being processed.
               self._session_process_ids: Processes processed in session.
               self.child_proc_whitelist: Noisy Procs for which we do not want relationships to be processed.
        """
        super().__init__()

        # Raise an error if the received processes are not a list.
        if type(process_ids) != list:
            raise TypeError("\"processes\" variable requires type list, got {}.".format(type(process_ids)))

        self._cb_api_key = cb_api_key
        self._cb_server_url = cb_server_url
        self.output_path = cb_output_path
        self._process_ids = process_ids
        self._alert_process_segments = None
        self.completed_process_segments = completed_procs
        self.process_data_store = []
        self._process_data = None
        self._process_id = None
        self._process_name = None
        self._session_process_ids = []
        self._child_proc_whitelist = ["services.exe", "ntoskrnl.exe", "smss.exe", "taskeng.exe"]

        # Check if the supplied URL needs the trailing "/" removing.
        if self._cb_server_url[-1] == "/":
            self._cb_server_url = self._cb_server_url[:-1]

        # Set the process API path.
        self._process_api_path = "{}/api/v1/process/".format(self._cb_server_url)

        # For each process in the passed alert IDs, do this.
        for process in self._process_ids:
            # This list is used for each alert loop.
            self._alert_process_segments = [process]
            self._process_handler()

    def _process_handler(self):
        """Handles the process events"""
        # This keeps going until all of the processes have been parsed.
        while self._alert_process_segments:
            self._alert_process_segments = list(set(self._alert_process_segments))
            self._process_data = None
            self._process_id = self._alert_process_segments[0]
            if self._process_id not in self._session_process_ids:
                self._get_process_data()
                self._session_process_ids.append(self._process_id)
            # Delete the processed record.
            index = self._alert_process_segments.index(self._process_id)
            del self._alert_process_segments[index]

    def _get_process_data(self):
        """Gets the process events."""
        # This section is rather complicated. Needs better commenting I think.
        process_id = self._process_id.split("/")[0]
        segment_id = self._process_id.split("/")[1]
        # Get the process data.
        self._process_data = self._get_cb_json("{}{}/{}/event".format(self._process_api_path, process_id, segment_id))
        if self._process_data:
            # Normally we have a process name, but on rare occasions, computer says: "no".
            try:
                self._process_name = self._process_data["process"]["process_name"]
            except KeyError:
                return

            # Store proc data if has not already been parsed.
            if self._process_id not in self.completed_process_segments:
                logging.info("Processing data for the process: \"{}\".".format(self._process_name))
                self.process_data_store.append(self._process_data["process"])
                self.completed_process_segments[self._process_id] = self._process_data["process"]["last_update"]
                process_children = True
            else:
                # Check if we need to reprocess children for new children.
                if self._process_data["process"]["last_update"] > self.completed_process_segments[self._process_id]:
                    self.completed_process_segments[self._process_id] = self._process_data["process"]["last_update"]
                    process_children = True
                else:
                    process_children = False

            # Do not store a whitelisted procs' child procs or parent as otherwise we can cancel Christmas.
            if any(whitelist_item.lower() == self._process_name.lower()
                   for whitelist_item in self._child_proc_whitelist):
                return

            # Store parent process id, even if data has already been parsed (it may have new children).
            if self._process_data["process"]["parent_unique_id"]:
                parent = self._factor_and_store_process_segment_id(
                    process=self._process_data["process"]["parent_unique_id"])
                if parent not in self._session_process_ids:
                    self._alert_process_segments.append(parent)

            # And get children (even if a process has already been parsed (we may see new children)).
            if process_children:
                if "childproc_complete" not in self._process_data["process"]:
                    return
                else:
                    for child_process in self._process_data["process"]["childproc_complete"]:
                        child = self._factor_and_store_process_segment_id(child_process.split("|")[1])
                        if child not in self._session_process_ids:
                            self._alert_process_segments.append(child)
                    return
        else:
            return

    @staticmethod
    def _factor_and_store_process_segment_id(process=None):
        """Factors the process and segment Ids.
        The process and segment ids in a process object are stored in the object's "unique-id".
        Args:
            process: a unique_id from a process object.
        """
        # Get the process id.
        process_id = process.split("-")[0:5]
        # Join the process id.
        process_id = "-".join(process_id)
        # Get the segment id.
        segment_id = process.split("-")[-1]
        # Get the real segment id by iterating over each char until we have a number.
        for index, number in enumerate(segment_id):
            if number != "0":
                segment_id = segment_id[index:]

        # Return process.
        process = process_id + "/" + segment_id
        return process

    def create_process_report(self, processes=None, title="timeline", do_modloads=True, do_supertimeline=True):
        """Creates a process timeline
        Args:
            processes: A list of dictionaries containing process data.
            title: Name of the sheet.
            do_modloads: Set to false as there as so many of them!
            do_supertimeline: Pass a true value to get a supertimeline.
        """
        if type(processes) != list:
            raise TypeError("\"processes\" variable requires type list, got {}.".format(type(processes)))

        all_results = []

        for process in processes:
            # Get the values.
            cmdline = process.get("cmdline", "-")
            username = process.get("username", "Unknown")
            start = process.get("start", "Unknown")
            hostname = process.get("hostname", "Unknown")
            process_name = process.get("process_name", "Unknown")
            path = process.get("path", "Unknown")
            process_md5 = process.get("process_md5", "Unknown")
            process_pid = process.get("process_pid", "Unknown")
            parent_pid = process.get("parent_pid", "Unknown")
            parent_name = process.get("parent_name", "Unknown")

            # Reformat the time string.
            if not start == "Unknown":
                start = start.replace("T", " ").replace("Z", "")

            # Store the basic data.
            all_results.append([start, "Process", "-", hostname, username, process_name, path, process_md5,
                                str(process_pid), str(parent_pid), parent_name, cmdline, "-", "-", "-", "-"])

            # Handle filemods.
            if process["filemod_count"] != 0:
                file_operation = ""
                for filemod in process["filemod_complete"]:
                    filemod = filemod.split("|")
                    if filemod[0] == "1":
                        file_operation = "First wrote to the file"
                    elif filemod[0] == "2":
                        file_operation = "First wrote to the file"
                    elif filemod[0] == "4":
                        file_operation = "Deleted the file"
                    elif filemod[0] == "8":
                        file_operation = "Last wrote to the file"
                    all_results.append([filemod[1], "File Mod", file_operation, hostname, username, process_name,
                                        filemod[2], process_md5, str(process_pid), str(parent_pid), parent_name,
                                        "-", "-", "-", "-", "-"])

            # Handle netconns.
            if process["netconn_count"] != 0:
                direction = ""
                for netconn in process["netconn_complete"]:
                    netconn = netconn.split("|")
                    # Handle IP Addresses passed as signed ints.
                    if "-" in str(netconn[1]):
                        ip_address = int(netconn[1])
                        ip_address += 2 ** 32
                    else:
                        ip_address = int(netconn[1])
                    if netconn[3] == "6":
                        protocol = "TCP"
                    else:
                        protocol = "UDP"
                    if netconn[5] == "true":
                        direction = "Outbound Connection"
                    elif netconn[5] == "false":
                        direction = "Inbound Connection"
                    all_results.append([netconn[0], "Network Connection", direction, hostname, username, process_name,
                                        path, process_md5, str(process_pid), str(parent_pid), parent_name, "-",
                                        str(netaddr.IPAddress(ip_address)), netconn[2], protocol, netconn[4]])

            # Handle modloads (at your peril).
            if do_modloads:
                if process["modload_count"] != 0:
                    for modload in process["modload_complete"]:
                        modload = modload.split("|")
                        all_results.append([modload[0], "Modload", "-", hostname, username, process_name, modload[2],
                                            modload[1], str(process_pid), str(parent_pid), parent_name,
                                            "-", "-", "-", "-", "-"])

            # Handle regmods.
            if process["regmod_count"] != 0:
                reg_operation = ""
                for regmod in process["regmod_complete"]:
                    regmod = regmod.split("|")
                    if regmod[0] == "1":
                        reg_operation = "Created the registry key"
                    elif regmod[0] == "2":
                        reg_operation = "First wrote to the registry key"
                    elif regmod[0] == "4":
                        reg_operation = "Deleted the key"
                    elif regmod[0] == "8":
                        reg_operation = "Deleted the value"
                    all_results.append([regmod[1], "Registry", reg_operation, hostname, username, process_name,
                                        regmod[2], "-", str(process_pid), str(parent_pid), parent_name,
                                        "-", "-", "-", "-", "-"])
        # Write the CSV
        if all_results:
            self._write_csv(title=title, events=all_results)
            if do_supertimeline:
                self._write_csv(title="supertimeline", events=all_results)
        else:
            logging.info("No new events to write!")
            return

    def _write_csv(self, title=None, events=None):
        """Writes the CSV data"""

        # Work out the report path based on the watchlist name.
        report_path = os.path.join(self.output_path, "{}.csv".format(title))

        # In case someone has it open.
        try:
            existing_events = []
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8", newline="") as f:
                    reader = csv.reader(f)
                    for index, row in enumerate(reader):
                        if index != 0:
                            existing_events.append(row)

            # Get the existing events
            existing_events += events
            # Convert the list items into unique tuples for de-duping (we can't hash a list of lists).
            events_temp = set(map(tuple, existing_events))
            # Convert the tuples back to lists.
            all_results = map(list, events_temp)
            # Store as a list
            all_results = sorted(list(all_results))

            with open(report_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Event Type", "Event Sub-Type", "Host", "Username",
                                 "Process Name", "Path", "Process MD5", "Process PID", "Parent PID", "Parent Name",
                                 "Cmdline", "Remote IP", "Remote Port", "Protocol", "Domain Name"])
                for row in all_results:
                    writer.writerow(row)

                logging.info("Report created/updated: \"{}\".csv".format(os.path.join(self.output_path, title)))

        except PermissionError:
            logging.error("Report could not be written (likely because it is already open).")


class CbBinary(_CbConnect):
    """Handles Binary Queries"""
    def __init__(self, cb_api_key=None, cb_server_url=None, cb_output_path=None, query=None):
        super().__init__()
        self._cb_api_key = cb_api_key
        self._cb_server_url = cb_server_url
        self._cb_output_path = cb_output_path
        self._query = query
        self.binary_hits = []

        # Check if the supplied URL needs the trailing "/" removing.
        if self._cb_server_url[-1] == "/":
            self._cb_server_url = self._cb_server_url[:-1]

        self._binary_query_path = "{}/api/v1/binary".format(self._cb_server_url)

    def do_binary_query(self, query=None):
        payload = {"q": query}
        binary_query = self._get_cb_json("{}".format(self._binary_query_path), payload=payload)
        # Do another search to get all results.
        if binary_query:
            if binary_query["total_results"] != 0 and binary_query["total_results"] != 1:
                rows = binary_query["total_results"]
                logging.info("{} Binary hits for \"{}\"".format(rows, query))
                payload = {"q": query, "rows": rows}
                all_binary_hits = self._get_cb_json("{}".format(self._binary_query_path), payload=payload)
                if all_binary_hits:
                    for hit in all_binary_hits["results"]:
                        self.binary_hits.append(hit)
                else:
                    logging.info("Error in getting binary data from server.")
                    return

            elif binary_query["total_results"] == 1:
                logging.info("1 Binary hit for \"{}\"".format(query))
                for hit in binary_query["results"]:
                    self.binary_hits.append(hit)

            elif binary_query["total_results"] == 0:
                logging.info("No Binary hits for the query \"{}\".".format(query))
                return

        else:
            logging.info("Error in getting binary data from server (for query \"{}\".".format(query))
            return

    def create_binary_report(self, hits=None):
        header = ["md5", "original filename", "observed filenames (pipe delimited)", "observed hosts count",
                  "observed hosts (pipe delimited)", "first seen", "last seen"]

        hits_store = []

        for hit in hits:
            md5 = hit["md5"]
            original_filename = hit["original_filename"]
            first_seen = hit["server_added_timestamp"]
            last_seen = hit["last_seen"]
            host_count = str(hit["host_count"])
            observed_filenames = ""
            for index, filename in enumerate(hit["observed_filename"], 1):
                if index != len(hit["observed_filename"]):
                    observed_filenames += filename.split("|")[0] + "|"
                else:
                    observed_filenames += filename.split("|")[0]

            observed_hosts = ""
            for index, host in enumerate(hit["endpoint"], 1):
                if index != len(hit["endpoint"]):
                    observed_hosts += host.split("|")[0] + "|"
                else:
                    observed_hosts += host.split("|")[0]

            row_to_store = [md5, original_filename, observed_filenames, host_count, observed_hosts, first_seen,
                            last_seen]

            hits_store.append(row_to_store)

        try:
            with open(os.path.join(self._cb_output_path, "binary_report.csv"), "w", encoding="utf=8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for row in hits_store:
                    writer.writerow(row)
                logging.info("Binary report created")
        except PermissionError:
            logging.error("Report could not be written (likely because it is already open).")


class CBAlert(_CbConnect):
    def __init__(self, cb_api_key=None, cb_server_url=None, watchlist_name=None):
        """Class for all CB process operations.
           Args:
                cb_api_key: CB API key.
                cb_server_url: CB server URL.
                watchlist_name: Optional parameter if we only want to focus on certain watchlists.
           Attributes:
               self._cb_api_key: CB API key.
               self._cb_server_url: CB server URL.
               self._alert_api_path: Path to CB API.
               self._watchlist_api_path: Path to CB API.
               self._watchlist_name: The watchlist name if provided.
               self.watchlist_details: Stores watchlist names and IDS.
               self.watchlist.process_hits: Stores process hits.
               self.watchlist.binary_hits: Stores process hits.
               self._clear_screen_command: The calling OS.
        """
        super().__init__()
        self._cb_api_key = cb_api_key
        self._cb_server_url = cb_server_url
        self._watchlist_name = watchlist_name
        self.watchlist_details = []
        self.watchlist_process_hits = {}
        self.watchlist_binary_hits = {}
        if platform.system() == "Windows":
            self._clear_screen_command = "cls"
        else:
            self._clear_screen_command = "clear"

        # Check if the supplied URL needs the trailing "/" removing.
        if self._cb_server_url[-1] == "/":
            self._cb_server_url = self._cb_server_url[:-1]

        self._alert_api_path = "{}/api/v1/alert".format(self._cb_server_url)
        self._watchlist_api_path = "{}/api/v1/watchlist".format(self._cb_server_url)

    def get_watchlist_details(self):
        watchlists = self._get_cb_json("{}".format(self._watchlist_api_path))
        if watchlists:
            logging.info("Got all watchlists from CB server.")
            for watchlist in watchlists:
                if self._watchlist_name:
                    if self._watchlist_name in watchlist["name"].lower():
                        self.watchlist_details.append(watchlist)
                else:
                    self.watchlist_details.append(watchlist)

    def get_alerts(self):
        print("Looking for new alerts...")
        # Get a count of all unresolved alerts.
        payload = {"q": "status:\"unresolved\""}
        alerts_summary = self._get_cb_json("{}".format(self._alert_api_path), payload=payload)

        if alerts_summary:
            if alerts_summary["total_results"] != 0:
                rows = alerts_summary["total_results"]
                print("{} unresolved alert(s)".format(rows))
                # Get all unresolved alerts.
                payload = {"q": "status:\"unresolved\"", "rows": rows}
                all_unresolved_alerts = self._get_cb_json("{}".format(self._alert_api_path), payload=payload)

                if all_unresolved_alerts:
                    for alert in all_unresolved_alerts["results"]:
                        if self._watchlist_name:
                            if self._watchlist_name.lower() not in alert["watchlist_name"].lower():
                                continue
                        watchlist_name = alert["watchlist_name"]

                        # Store the binary alerts.
                        if alert["alert_type"] == "watchlist.hit.query.binary":
                            if watchlist_name not in self.watchlist_binary_hits:
                                self.watchlist_binary_hits[watchlist_name] = {}
                                self.watchlist_binary_hits[watchlist_name]["hits"] = []
                            self.watchlist_binary_hits[watchlist_name]["hits"].append(alert)

                        # Store the process alerts.
                        if alert["alert_type"] == "watchlist.hit.query.process":
                            if watchlist_name not in self.watchlist_process_hits:
                                self.watchlist_process_hits[watchlist_name] = {}
                                self.watchlist_process_hits[watchlist_name]["hits"] = []
                            self.watchlist_process_hits[watchlist_name]["hits"].append(alert)

                else:
                    print("No connection to CB Server!")
                    time.sleep(2)
                    os.system(self._clear_screen_command)
        else:
            print("No connection to CB Server!")
            time.sleep(2)
            os.system(self._clear_screen_command)
