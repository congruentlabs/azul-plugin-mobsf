import pytest
from azul_runner import DATA_HASH, FV, Event, JobResult, State

from .common import BaseMobSFTest, load_test_file, make_fake_apk


class TestConfig(BaseMobSFTest):
    def test_plugin_without_auth_token(self):
        """Test plugin initialization without authentication token."""
        with self.assertRaises(RuntimeError):
            self.do_execution(
                data_in=[("content", make_fake_apk())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "mobsf_auth_token": ""},
                no_multiprocessing=True,
            )

    def test_missing_optional_fields(self):
        """Test handling of reports missing optional fields."""
        minimal_report = {
            "app_name": "MinimalApp",
            "app_type": "android",
            "file_name": "minimal.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.minimal.app",
            "min_sdk": "21",
            "target_sdk": "30",
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "minimal.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=minimal_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("MinimalApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.minimal.app")],
            "file_name": [FV("minimal.apk")],
            "file_size": [FV("1MB")],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_network_error_during_initialization(self):
        """Test network error when initializing plugin (missing server)."""
        with self.assertRaises(RuntimeError):
            self.do_execution(
                data_in=[("content", make_fake_apk())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "mobsf_server": ""},
                no_multiprocessing=True,
            )

    def test_invalid_server_url(self):
        """Test with invalid server URL format."""
        with self.assertRaises(RuntimeError):
            self.do_execution(
                data_in=[("content", make_fake_apk())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "mobsf_server": "not-a-valid-url"},
                no_multiprocessing=True,
            )

    def test_invalid_integer_config_timeout(self):
        """Test with invalid integer configuration for start_timeout."""
        with self.assertRaises(ValueError):
            self.do_execution(
                data_in=[("content", make_fake_apk())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "start_timeout": "not-an-int"},
                no_multiprocessing=True,
            )

    def test_invalid_integer_config_poll_interval(self):
        """Test with invalid integer configuration for poll_interval."""
        with self.assertRaises(ValueError):
            self.do_execution(
                data_in=[("content", make_fake_apk())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "poll_interval": "invalid"},
                no_multiprocessing=True,
            )

    def test_invalid_integer_config_retry_count(self):
        """Test with invalid integer configuration for api_retry_count."""
        with self.assertRaises(ValueError):
            self.do_execution(
                data_in=[("content", make_fake_apk())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "api_retry_count": "bad"},
                no_multiprocessing=True,
            )

    def test_filename_without_extension_adds_apk(self):
        """Test that files without extension get .apk added as default."""
        minimal_report = {
            "app_name": "TestApp",
            "app_type": "android",
            "file_name": "sample_apk_no_ext.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
        }

        data = load_test_file("sample_apk_no_ext")
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "sample_apk_no_ext.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=minimal_report)

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("TestApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.test.app")],
            "file_name": [FV("sample_apk_no_ext.apk")],
            "file_size": [FV("1MB")],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_filename_without_extension_defaults_to_apk(self):
        """Test that files without extension default to .apk when file_format not available."""
        minimal_report = {
            "app_name": "TestApp",
            "app_type": "swift",
            "file_name": "sample_ipa_no_ext.apk",
            "size": "2MB",
            "app_version": "1.0",
            "build": "1",
            "bundle_name": "com.test.app",
            "min_sdk": "12.0",
            "target_sdk": "15.0",
        }

        data = load_test_file("sample_ipa_no_ext")
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "sample_ipa_no_ext.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=minimal_report)

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("TestApp")],
            "app_type": [FV("swift")],
            "bundle_id": [FV("")],
            "file_name": [FV("sample_ipa_no_ext.apk")],
            "file_size": [FV("2MB")],
            "min_version": [FV("")],
            "sdk_name": [FV("")],
            "target_version": [FV("")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_filename_with_invalid_extension_replaces_with_apk(self):
        """Test that files with invalid extensions get .apk added as default."""
        minimal_report = {
            "app_name": "TestApp",
            "app_type": "android",
            "file_name": "sample_apk_invalid_ext.txt.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
        }

        data = load_test_file("sample_apk_invalid_ext.txt")
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "sample_apk_invalid_ext.txt.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=minimal_report)

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("TestApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.test.app")],
            "file_name": [FV("sample_apk_invalid_ext.txt.apk")],
            "file_size": [FV("1MB")],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_filename_without_extension_no_file_format_defaults_to_apk(self):
        """Test that files without extension and no file_format default to .apk."""
        minimal_report = {
            "app_name": "TestApp",
            "app_type": "android",
            "file_name": "sample_apk_no_ext.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
        }

        data = load_test_file("sample_apk_no_ext")
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "sample_apk_no_ext.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=minimal_report)

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("TestApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.test.app")],
            "file_name": [FV("sample_apk_no_ext.apk")],
            "file_size": [FV("1MB")],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )
