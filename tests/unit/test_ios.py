from azul_runner import DATA_HASH, FV, Event, JobResult, State

from .common import BaseMobSFTest, load_test_data, make_fake_ipa


class TestIOS(BaseMobSFTest):
    def test_ipa_analysis(self):
        dummy_ipa_report = {
            "app_name": "TestApp",
            "app_type": "swift",
            "file_name": "test.ipa",
            "size": "2MB",
            "app_version": "1.0.0",
            "build": "1",
            "bundle_id": "com.test.app",
            "min_os_version": "13.0",
            "platform": "iPhone OS",
            "sdk_name": "iPhone OS",
            "findings": [
                {"title": "App Transport Security", "section": "info.plist", "description": "ATS is enabled"},
                {"title": "Camera Usage", "section": "permissions", "description": "App requests camera access"},
            ],
            "secrets": ["API_KEY=test123"],
        }

        data = make_fake_ipa()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "ipa", "file_name": "test.ipa"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
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
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=dummy_ipa_report)
        result = self.do_execution(
            data_in=[("content", data)],
            config={**self.PLUGIN_TO_TEST_CONFIG, "filter_data_types": {"content": ["archive/zip", "ios/ipa"]}},
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("TestApp")],
            "app_type": [FV("swift")],
            "bundle_id": [FV("com.test.app")],
            "file_name": [FV("test.ipa")],
            "file_size": [FV("2MB")],
            "manifest_findings": [FV("App Transport Security: ATS is enabled")],
            "min_version": [FV("13.0")],
            "permissions": [FV("App requests camera access")],
            "sdk_name": [FV("iPhone OS")],
            "secrets": [FV("API_KEY=test123")],
            "target_version": [FV("iPhone OS")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0.0")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_ios_full_features(self):
        """Test with real MobSF IPA report from sample_basic_ipa.json."""
        # Load real MobSF IPA report
        full_ipa_report = load_test_data("sample_basic_ipa.json")

        data = make_fake_ipa()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={
                "hash": file_hash,
                "scan_type": "ipa",
                "file_name": "a42db180958b17edff843dd8893f4caac6b754b7f8f80d24fd9a685a32dcf34d.ipa",
            },
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=full_ipa_report)
        result = self.do_execution(
            data_in=[("content", data)],
            config={**self.PLUGIN_TO_TEST_CONFIG, "filter_data_types": {"content": ["archive/zip", "ios/ipa"]}},
            no_multiprocessing=True,
        )

        # Expected features based on sample_basic_ipa.json content
        expected_features = {
            "app_name": [FV("EroEroMovie")],
            "app_type": [FV("Swift")],
            "bundle_id": [FV("s.EroEroMovie")],
            "detected_trackers": [FV(0)],
            "domains": [
                FV("ocsp.apple.com (Australia, Sydney) - Not OFAC Listed"),
                FV("www.apple.com (Korea (Republic of), Seoul) - Not OFAC Listed"),
            ],
            "file_name": [FV("a42db180958b17edff843dd8893f4caac6b754b7f8f80d24fd9a685a32dcf34d.ipa")],
            "file_size": [FV("4.46MB")],
            "min_version": [FV("8.1")],
            "sdk_name": [FV("iphoneos8.1")],
            "target_version": [FV("8.1")],
            "total_trackers": [FV(432)],
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

    def test_ios_no_findings(self):
        ios_no_findings = {
            "app_name": "CleanIOSApp",
            "app_type": "swift",
            "file_name": "clean.ipa",
            "size": "2MB",
            "app_version": "1.0",
            "build": "1",
            "bundle_id": "com.clean.app",
            "min_os_version": "13.0",
            "platform": "iPhone OS",
            "findings": [],
        }

        data = make_fake_ipa()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "ipa", "file_name": "clean.ipa"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=ios_no_findings)
        result = self.do_execution(
            data_in=[("content", data)],
            config={**self.PLUGIN_TO_TEST_CONFIG, "filter_data_types": {"content": ["archive/zip", "ios/ipa"]}},
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("CleanIOSApp")],
            "app_type": [FV("swift")],
            "bundle_id": [FV("com.clean.app")],
            "file_name": [FV("clean.ipa")],
            "file_size": [FV("2MB")],
            "min_version": [FV("13.0")],
            "sdk_name": [FV("")],
            "target_version": [FV("iPhone OS")],
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
