from azul_runner import DATA_HASH, JobResult, State

from .common import BaseMobSFTest, make_fake_apk


class TestErrors(BaseMobSFTest):
    def test_scan_error(self):
        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "test.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={
                "logs": [
                    {
                        "timestamp": "2025-12-15 00:29:00",
                        "status": "Starting Analysis",
                        "exception": "Analysis error: Failed to extract APK",
                    }
                ]
            },
        )
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        # Scan failures should raise MobSFError which becomes ERROR_EXCEPTION
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="MobSF scan failed: Analysis error: Failed to extract APK",
                )
            ),
        )

    def test_error_status(self):
        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "test.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={
                "logs": [
                    {
                        "timestamp": "2025-12-15 00:30:00",
                        "status": "Processing",
                        "exception": "Unexpected error occurred during scan",
                    }
                ]
            },
        )
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        # Error status should raise MobSFError which becomes ERROR_EXCEPTION
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="MobSF scan failed: Unexpected error occurred during scan",
                )
            ),
        )

    def test_timeout(self):
        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "test.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        # Add enough Pending responses to cover polling until timeout (1s timeout with 1s interval = 2-3 polls)
        for _ in range(3):
            self.httpx_mock.add_response(
                method="POST",
                url="http://localhost/api/v1/scan_logs",
                json={
                    "logs": [{"timestamp": "2025-12-15 00:29:00", "status": "Starting Analysis", "exception": None}]
                },
            )

        result = self.do_execution(
            data_in=[("content", data)],
            config={**self.PLUGIN_TO_TEST_CONFIG, "start_timeout": 1, "poll_interval": 1},
            no_multiprocessing=True,
        )

        # Timeout should raise MobSFError which becomes ERROR_EXCEPTION
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.ERROR_EXCEPTION, failure_name="MobSF scan timeout after 1 seconds")),
        )

    def test_http_500_error_on_upload(self):
        # Check for existing report (404 = not found)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        # Check tasks (empty)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        # Upload returns 500 error - this should raise HTTPStatusError -> ERROR_NETWORK
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/upload", status_code=500)

        data = make_fake_apk()
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        assert result.state.label == State.Label.ERROR_NETWORK

    def test_http_404_error_on_report(self):
        # Mock initial check for existing report (404 = not found, continue to upload)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        # Mock scan logs check (400 = no scan found)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        # Mock upload and scan endpoints successfully
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": "h", "scan_type": "apk", "file_name": "f.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        # Mock final report_json with 404 - this will cause an HTTP status error
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)

        data = make_fake_apk()
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )
        assert result.state.label == State.Label.ERROR_NETWORK

    def test_scan_logs_500_does_not_upload(self):
        """A MobSF scan status failure should not be treated as an absent scan."""
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=500)

        data = make_fake_apk()
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        assert result.state.label == State.Label.ERROR_EXCEPTION
        assert not [request for request in self.httpx_mock.get_requests() if request.url.path == "/api/v1/upload"]

    def test_mobsf_json_error_response(self):
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/report_json",
            json={"error": True, "error_value": "File not found in MobSF database"},
        )
        data = make_fake_apk()
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="MobSF returned error checking for existing scan",
                    message="File not found in MobSF database",
                )
            ),
        )
