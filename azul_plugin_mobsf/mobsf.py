"""Handle the API requests to MobSF on behalf of the plugin."""

import datetime
import logging
import time
from typing import Any, Dict, Optional

import httpx
from azul_runner import Job, State, settings

logger = logging.getLogger(__name__)


def _detect_file_extension(file_format: str) -> Optional[str]:
    """Determine appropriate file extension based on file_format.

    Returns the appropriate file extension for MobSF, or None if not recognized.
    MobSF supports: APK, APKS, XAPK, AAB, JAR, AAR, SO, IPA, DYLIB, A, ZIP, APPX
    However, the API will reject files uploaded without an extension on the file name.
    At the moment we're only supporting APK and IPA formats in the plugin config.

    Args:
        file_format: Format string like "android/apk" or "ios/ipa"
    """
    if not file_format:
        return None

    # Extract extension from format like "android/apk" or "ios/ipa"
    if "/" in file_format:
        extension = file_format.split("/")[-1].lower()
        # Validate it's a supported MobSF format
        if extension in ("apk", "apks", "xapk", "aab", "jar", "aar", "so", "ipa", "dylib", "a", "zip", "appx"):
            return f".{extension}"

    return None


class MobSFError(RuntimeError):
    """Exception raised to indicate that the MobSF returned a failure condition to a request.

    Optional second parameter `mobsf_message` records the message returned by mobsf.
    """

    mobsf_message: str = None  # Error message returned by mobsf

    def __init__(self, message=None, mobsf_message: str = None):
        super().__init__(message)
        self.mobsf_message = mobsf_message


def _check_error(resp: httpx.Response, context: str) -> Optional[State]:
    """Utility function to check if mobsf returned an error and raise a MobSFError if so."""
    # Raise an exception for non-'OK' responses
    resp.raise_for_status()

    # Check for MobSF errors if the response is JSON
    # Only trigger on boolean True, not string values in "error" field
    # Handle both dict responses (most endpoints) and list responses (/tasks endpoint)
    if resp.headers["content-type"].startswith("application/json"):
        json_data = resp.json()
        if isinstance(json_data, dict) and json_data.get("error") is True:
            # Note that the JSON for /report/ does NOT seem to contain {'error': False, ...} if it succeeded,
            #  so we need to use get() rather than resp.json()['error'] as the key may be absent.
            error_msg = json_data.get("error_value", "Unknown error")
            logger.fatal(f"MobSF error {context}: " + str(error_msg))
            raise MobSFError(f"MobSF returned error {context}", mobsf_message=str(error_msg))


class MobSF:
    """Methods for handling plugin tasks for MobSF, such as submitting and waiting for jobs, or fetching a report."""

    client: httpx.Client

    def __init__(self, cfg: settings.Settings):
        self.cfg = cfg

        if self.cfg.mobsf_auth_token:
            auth_header = {"Authorization": f"{self.cfg.mobsf_auth_token}"}
        else:
            auth_header = None

        self.client = httpx.Client(
            base_url=f"{self.cfg.mobsf_server}/api/v1",
            headers=auth_header,
            transport=httpx.HTTPTransport(retries=self.cfg.api_retry_count),
            timeout=self.cfg.request_timeout,
        )
        logger.info(
            f"Initialised with base url '{self.cfg.mobsf_server}/api/v1', {self.cfg.request_timeout}s timeout and "
            "{self.cfg.api_retry_count} retries"
        )

    def __del__(self):
        """Ensure the httpx connection is closed on deletion."""
        self.client.close()

    def _check_existing_scan(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check if a file with this hash has already been analyzed."""
        try:
            response = self.client.post("/report_json", data={"hash": file_hash})
            _check_error(response, "checking for existing scan")

            if response.status_code == 200:
                return response.json()

        except httpx.HTTPError as e:
            # Handle connection errors (e.g., DNS failure, refused connection)
            if isinstance(e, httpx.ConnectError):
                # Connection error: treat as file not found or network unavailable
                logger.error(f"Network error checking existing scan: {e}")
                return None
            if hasattr(e, "response") and e.response and e.response.status_code == 404:
                # File not found is an expected condition
                return None
            logger.error(f"Error checking existing scan: {e}")
            raise MobSFError(f"Error checking existing scan: {e}")

        return None

    def _check_scan_status(self, file_hash: str) -> Optional[str]:
        """Check if there's an active scan for this file hash.

        Returns:
        - "completed" if scan finished (status "Saving to Database" found)
        - "in_progress" if scan is running
        - None if no scan found (400 response)
        """
        try:
            response = self.client.post("/scan_logs", data={"hash": file_hash})

            if response.status_code == 400:
                # Bad request means no scan has been started for this hash
                logger.info(f"No active scan found for hash: {file_hash}")
                return None

            _check_error(response, "checking scan logs")

            if response.status_code == 200:
                logs_data = response.json()
                logs = logs_data.get("logs", [])

                if not logs:
                    logger.info("Scan logs empty, scan may be starting")
                    return "in_progress"

                # Check for exceptions/errors in logs
                for log_entry in logs:
                    exception = log_entry.get("exception")
                    if exception:
                        logger.error(f"Scan failed with exception: {exception}")
                        raise MobSFError(f"MobSF scan failed: {exception}")

                # Check if scan has completed (look for database save status)
                for log_entry in logs:
                    status = log_entry.get("status", "")
                    if status in ("Saving to Database", "Updating Database..."):
                        logger.info(f"Scan completed for hash: {file_hash} (status: {status})")
                        return "completed"

                # Scan is in progress but not completed yet
                latest_status = logs[-1].get("status", "Unknown") if logs else "Unknown"
                logger.info(f"Scan in progress - latest status: {latest_status}")
                return "in_progress"

        except httpx.HTTPError as e:
            if hasattr(e, "response") and e.response and e.response.status_code == 400:
                # 400 means no scan found
                return None
            logger.warning(f"Error checking scan logs: {e}")
            return None

        return None

    def find_or_submit(self, job: Job) -> tuple[Dict[str, Any], bool]:
        """Checks for an existing job for this file in MobSF, and submits the file if not present.

        Returns a tuple of (task_data, is_complete) where:
        - task_data: dictionary from MobSF with hash and metadata
        - is_complete: True if scan is already complete, False if we need to wait
        """
        file_hash = job.event.entity.md5

        if not file_hash:
            # MD5 hash is required - this should always be provided by Azul
            logger.error("No MD5 hash available in job entity")
            raise MobSFError("MD5 hash is required but not present in job entity")

        # Check if MobSF already has a report or active scan for this hash
        logger.info(f"Checking MobSF for existing analysis of hash: {file_hash}")

        # Step 1: Check if report already exists
        existing_scan = self._check_existing_scan(file_hash)
        if existing_scan:
            logger.info(f"Report already exists for hash: {file_hash}")
            return existing_scan, True  # Report already exists, no need to wait

        # Step 2: Check if scan is active or completed
        scan_status = self._check_scan_status(file_hash)
        if scan_status == "completed":
            # Scan completed, fetch the report
            logger.info(f"Scan completed, fetching report for hash: {file_hash}")
            existing_scan = self._check_existing_scan(file_hash)
            if existing_scan:
                return existing_scan, True
            # If report still not available, fall through to wait
            logger.warning("Scan marked complete but report not available yet, will wait")
            return {"hash": file_hash}, False
        elif scan_status == "in_progress":
            # Scan is already running, just wait for it
            logger.info(f"Scan already in progress for hash: {file_hash}, will wait for completion")
            return {"hash": file_hash}, False

        # No existing report or active scan found in MobSF - need to upload
        logger.info(f"No existing report or scan found in MobSF for hash: {file_hash}")

        # Step 3: No existing scan or report, need to upload file to MobSF
        logger.info("No existing scan found, uploading file to MobSF")

        filenames = [f.value for f in job.event.entity.features if f.name == "filename"]
        # MobSF accepts bare data-stream in file submission
        filename = sorted(filenames)[0] if filenames else "sample"

        # Ensure filename has a valid extension for MobSF
        # MobSF requires: APK, APKS, XAPK, AAB, JAR, AAR, SO, IPA, DYLIB, A, ZIP, APPX
        if "." not in filename or filename.rsplit(".", 1)[1].lower() not in (
            "apk",
            "apks",
            "xapk",
            "aab",
            "jar",
            "aar",
            "so",
            "ipa",
            "dylib",
            "a",
            "zip",
            "appx",
        ):
            logger.warning(f"Filename '{filename}' missing valid extension, attempting to detect file type")
            file_format = getattr(job.event.entity, "file_format", None)
            # Handle file_format as bytes or string
            if file_format and isinstance(file_format, bytes):
                file_format = file_format.decode("utf-8", errors="ignore")
            detected_ext = _detect_file_extension(file_format or "")
            if detected_ext:
                filename = f"{filename}{detected_ext}"
                logger.info(f"Added detected extension based on file_format: {filename}")
            else:
                # Default to .apk if we can't detect
                filename = f"{filename}.apk"
                logger.warning(f"Could not detect file type, defaulting to .apk: {filename}")

        data = job.get_data()
        files = {"file": (filename, data)}

        response = self.client.post("/upload", files=files)
        _check_error(response, "submitting job")

        if response.status_code != 200:
            raise MobSFError(f"Upload failed with status code: {response.status_code}")

        response_data = response.json()
        if not response_data.get("hash"):
            raise MobSFError("Upload response missing file hash")

        logger.info(f"File uploaded successfully with hash: {response_data.get('hash')}")

        # Step 4: Initiate the scan
        scan_response = self.client.post(
            "/scan",
            data={
                "hash": response_data.get("hash"),
                "scan_type": response_data.get("scan_type"),
                "file_name": response_data.get("file_name"),
            },
        )
        _check_error(scan_response, "initiating scan")

        if scan_response.status_code != 200:
            raise MobSFError(f"Scan initiation failed with status code: {scan_response.status_code}")

        logger.info(f"Scan initiated for hash: {response_data.get('hash')}")
        return response_data, False  # Just uploaded and initiated scan, need to wait for completion

    def wait_for_completion(self, task_data: Dict[str, Any]) -> None:
        """Wait until the specified MobSF scan is completed.

        Polls /scan_logs and waits for "Saving to Database" status.
        Raises MobSFError if the scan times out or fails.
        """
        file_hash = task_data.get("hash")
        if not file_hash:
            raise MobSFError("Task data missing file hash")

        submit_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        while True:
            # Poll scan logs to check status
            scan_status = self._check_scan_status(file_hash)

            if scan_status == "completed":
                logger.info("Scan completed successfully (Saving to Database)")
                break
            elif scan_status == "in_progress":
                # Continue waiting
                pass
            elif scan_status is None:
                # No scan logs found - this is unusual after upload, but continue waiting
                logger.warning(f"No scan logs found for hash {file_hash}, scan may be starting")

            time_waited = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - submit_time).seconds
            if time_waited > self.cfg.start_timeout:
                logger.fatal(f"MobSF scan did not complete within {self.cfg.start_timeout} seconds")
                raise MobSFError(f"MobSF scan timeout after {self.cfg.start_timeout} seconds")

            logger.info(f"Waiting for scan to complete ({time_waited}s)")
            time.sleep(self.cfg.poll_interval)

    def fetch_job_report(self, task_data: Dict[str, Any]) -> dict:
        """Fetch the MobSF JSON report for a given task as a python dict."""
        file_hash = task_data.get("hash")
        if not file_hash:
            raise MobSFError("Task data missing file hash")

        response = self.client.post("/report_json", data={"hash": file_hash})
        _check_error(response, "while fetching job report")

        report_data = response.json()
        if not report_data:
            raise MobSFError("Empty report received from MobSF")

        return report_data
