"""Tests for scenarios where a task already exists in the MobSF queue."""

from azul_runner import State

from .common import BaseMobSFTest, make_fake_apk, make_fake_ipa


class TestExistingTask(BaseMobSFTest):
    """Test cases for when a task already exists in the MobSF task queue."""

    def test_existing_task_in_progress(self):
        """Test that we don't re-upload when a task is already in progress."""
        dummy_apk_report = {
            "app_name": "Sample APK",
            "app_type": "android",
            "file_name": "test.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
        }

        data = make_fake_apk()

        # 1. Check for existing report - none found
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)

        # 2. Check scan logs - scan is in progress
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={
                "logs": [{"timestamp": "2025-12-15 00:29:30", "status": "Performing Malware check", "exception": None}]
            },
        )

        # 3. No upload should happen - go straight to polling
        # Poll /scan_logs for status until Success
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={
                "logs": [{"timestamp": "2025-12-15 00:30:00", "status": "Performing Malware check", "exception": None}]
            },
        )
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )

        # 4. Fetch final report
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=dummy_apk_report)

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        # Verify execution succeeded and found the app
        self.assertEqual(result.state.label, State.Label.COMPLETED)
        self.assertEqual(len(result.events), 1)
        self.assertIn("app_name", result.events[0].features)
        self.assertEqual(result.events[0].features["app_name"][0].value, "Sample APK")

    def test_existing_task_completed(self):
        """Test handling when task shows Success but report endpoint still 404s briefly."""
        dummy_apk_report = {
            "app_name": "Sample APK",
            "app_type": "android",
            "file_name": "test.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
        }

        data = make_fake_apk()
        # 1. Check for existing report - none found yet
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)

        # 2. Check scan logs - scan shows as completed
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )

        # 3. Code finds completed status, tries to fetch report and succeeds
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=dummy_apk_report)

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        # Verify execution succeeded
        self.assertEqual(result.state.label, State.Label.COMPLETED)
        self.assertEqual(len(result.events), 1)

    def test_existing_task_pending(self):
        """Test that we wait for a task that's in Pending state."""
        dummy_ipa_report = {
            "app_name": "Sample IPA",
            "app_type": "swift",
            "file_name": "test.ipa",
            "size": "2MB",
            "app_version": "1.0",
            "build": "1",
            "bundle_id": "com.test.app",
            "min_os_version": "12.0",
            "platform": "15.0",
        }

        data = make_fake_ipa()

        # 1. Check for existing report - none found
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)

        # 2. Check scan logs - scan is starting (Pending)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:28:00", "status": "Starting Analysis", "exception": None}]},
        )

        # 3. Poll status - goes from Pending -> Processing -> Success
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:29:00", "status": "Starting Analysis", "exception": None}]},
        )
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={
                "logs": [{"timestamp": "2025-12-15 00:30:00", "status": "Performing Malware check", "exception": None}]
            },
        )
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )

        # 4. Fetch final report
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=dummy_ipa_report)

        result = self.do_execution(
            data_in=[("content", data)],
            config={**self.PLUGIN_TO_TEST_CONFIG, "filter_data_types": {"content": ["archive/zip", "ios/ipa"]}},
            no_multiprocessing=True,
        )

        # Verify execution succeeded
        self.assertEqual(result.state.label, State.Label.COMPLETED)
        self.assertEqual(len(result.events), 1)
