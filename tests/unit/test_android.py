from azul_runner import DATA_HASH, FV, Event, EventData, JobResult, State

from .common import MOBSF_FAKE_APK_RECORD_URL, BaseMobSFTest, load_test_data, make_fake_apk


class TestAndroid(BaseMobSFTest):
    def test_apk_analysis(self):
        dummy_apk_report = {
            "app_name": "TestApp",
            "app_type": "android",
            "file_name": "test.apk",
            "size": "1MB",
            "version_name": "1.0.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "main_activity": "com.test.app.MainActivity",
            "activities": ["com.test.app.MainActivity", "com.test.app.SecondActivity"],
            "services": ["com.test.app.SyncService"],
            "receivers": ["com.test.app.BootReceiver"],
            "providers": ["com.test.app.DataProvider"],
            "exported_activities": ["com.test.app.MainActivity"],
            "permissions": {
                "android.permission.INTERNET": {
                    "status": "dangerous",
                    "info": "Network access",
                    "description": "Allows the app to access the internet",
                }
            },
            "manifest_analysis": {
                "manifest_findings": [
                    {"severity": "high", "title": "Backup Enabled", "description": "App data can be backed up"}
                ],
                "manifest_summary": {"high": 1, "warning": 0, "info": 0},
            },
            "certificate_analysis": {
                "certificate_findings": [["warning", "SHA1 used", "SHA1 signing algorithm is weak"]]
            },
            "secrets": ["API_KEY=test123"],
        }

        # Mock the HTTP flow: check existing (404), check tasks (empty), upload, poll status, fetch report
        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        # 1. Check for existing scan - returns 404
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)

        # 2. Check task queue - no existing tasks
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)

        # 3. Upload file
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "test.apk"},
        )

        # 4. Initiate scan
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})

        # 5. Poll for status (check /scan_logs until Success)
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

        # 5. Fetch final report
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=dummy_apk_report)
        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "activities": [FV("com.test.app.MainActivity"), FV("com.test.app.SecondActivity")],
            "app_name": [FV("TestApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.test.app")],
            "certificate_analysis": [FV("warning: SHA1 used")],
            "exported_activities": [FV("com.test.app.MainActivity")],
            "file_name": [FV("test.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "main_activity": [FV("com.test.app.MainActivity")],
            "providers": [FV("com.test.app.DataProvider")],
            "receivers": [FV("com.test.app.BootReceiver")],
            "services": [FV("com.test.app.SyncService")],
            "manifest_findings": [FV("high: Backup Enabled - App data can be backed up")],
            "manifest_summary": [FV("High: 1, Warning: 0, Info: 0")],
            "min_version": [FV("21")],
            "permissions": [
                FV("android.permission.INTERNET (dangerous): Network access - Allows the app to access the internet")
            ],
            "secrets": [FV("API_KEY=test123")],
            "target_version": [FV("30")],
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

    def test_android_full_features(self):
        """Test with real MobSF report from sample_basic_apk.json."""
        # Load real MobSF report
        full_apk_report = load_test_data("sample_basic_apk.json")

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "wildfire-test-apk-file.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=full_apk_report)
        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        # Expected features based on wildfire.json content
        expected_features = {
            "activities": [FV("com.panw.panwapktest.MainActivity")],
            "android_api": [FV("info: Local File I/O Operations (used in 1 files)")],
            "apkid": [FV("classes.dex - Compiler: dx (possible dexmerge)"), FV("classes.dex - Manipulator: dexmerge")],
            "app_name": [FV("PanwAPKTest")],
            "app_type": [FV("apk")],
            "bundle_id": [FV("com.panw.panwapktest")],
            "certificate_analysis": [
                FV("info: Application is signed with a code signing certificate"),
                FV(
                    "warning: Application is signed with v1 signature scheme, making it vulnerable to Janus vulnerability on Android 5.0-8.0, if signed only with v1 signature scheme. Applications running on Android 5.0-7.0 signed with v1, and v2/v3 scheme is also vulnerable."
                ),
                FV(
                    "warning: Application is signed with SHA1withRSA. SHA1 hash algorithm is known to have collision issues. The manifest file indicates SHA256withRSA is in use."
                ),
            ],
            "code_analysis": [
                FV(
                    "high: Debug configuration enabled. Production builds must not be debuggable. (CVSS: 5.4, CWE-919: Weaknesses in Mobile Applications)"
                )
            ],
            "detected_trackers": [FV(0)],
            "file_name": [FV("wildfire-test-apk-file.apk")],
            "file_size": [FV("1.38MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "main_activity": [FV("com.panw.panwapktest.MainActivity")],
            "manifest_findings": [
                FV(
                    "high: App can be installed on a vulnerable unpatched Android version Android 4.3-4.3.1, [minSdk=18] - This application can be installed on an older version of android that has multiple unfixed vulnerabilities. These devices won't receive reasonable security updates from Google. Support an Android version => 10, API 29 to receive reasonable security updates."
                ),
                FV(
                    "high: Debug Enabled For App [android:debuggable=true] - Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes."
                ),
                FV(
                    "warning: Application Data can be Backed up [android:allowBackup=true] - This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device."
                ),
            ],
            "manifest_summary": [FV("High: 2, Warning: 1, Info: 0")],
            "min_version": [FV("18")],
            "target_version": [FV("18")],
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

    def test_permissions_as_simple_strings(self):
        simple_perms_report = {
            "app_name": "SimplePermsApp",
            "app_type": "android",
            "file_name": "simple.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.simple.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "permissions": {
                "android.permission.INTERNET": "String permission value",
                "android.permission.CAMERA": {"status": "dangerous", "info": "Camera", "description": "Camera access"},
            },
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "simple.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(
            method="POST", url="http://localhost/api/v1/report_json", json=simple_perms_report
        )
        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("SimplePermsApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.simple.app")],
            "file_name": [FV("simple.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "min_version": [FV("21")],
            "permissions": [
                FV("android.permission.CAMERA (dangerous): Camera - Camera access"),
                FV("android.permission.INTERNET"),
            ],
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

    def test_exported_activities_as_string(self):
        string_activities_report = {
            "app_name": "StringApp",
            "app_type": "android",
            "file_name": "string.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.string.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "exported_activities": "[Activity1, Activity2, Activity3]",
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "string.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(
            method="POST", url="http://localhost/api/v1/report_json", json=string_activities_report
        )
        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "app_name": [FV("StringApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.string.app")],
            "exported_activities": [FV("Activity1"), FV("Activity2"), FV("Activity3")],
            "file_name": [FV("string.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
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

    def test_exported_activities_empty_list(self):
        no_exported_report = {
            "app_name": "NoExportedApp",
            "app_type": "android",
            "file_name": "noexported.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.noexported.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "exported_activities": [],
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "noexported.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=no_exported_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("NoExportedApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.noexported.app")],
            "file_name": [FV("noexported.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
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

    def test_behavior_trackers_and_security_score(self):
        behavior_report = {
            "app_name": "BehaviorApp",
            "app_type": "android",
            "file_name": "behavior.apk",
            "size": "2MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.behavior.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "behaviour": {
                "telephony": ["Sending SMS", "Reading SMS"],
                "file_operations": ["Reading external storage"],
            },
            "trackers": {"total_trackers": 3},
            "security_score": 45,
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "behavior.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=behavior_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("BehaviorApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.behavior.app")],
            "file_name": [FV("behavior.apk")],
            "file_size": [FV("2MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "version_name": [FV("1.0")],
            "version_code": [FV("1")],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "behaviour": [
                FV("telephony: Sending SMS"),
                FV("telephony: Reading SMS"),
                FV("file_operations: Reading external storage"),
            ],
            "security_score": [FV(45)],
            "total_trackers": [FV(3)],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_debug_field_is_none(self):
        """Test that plugin handles debug field being explicitly None without crashing."""
        report = {
            "app_name": "TestApp",
            "app_type": "android",
            "file_name": "test.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "debug": None,
        }

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
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("TestApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.test.app")],
            "file_name": [FV("test.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
        }

        # Should complete without error even though debug is None
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_debug_log_extraction(self):
        log_report = {
            "app_name": "LogApp",
            "app_type": "android",
            "file_name": "log.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.log.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "debug": {
                "log": "Analysis started at 2024-01-01 10:00:00\nProcessing APK...\nAnalysis completed at 2024-01-01 10:05:00"
            },
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "log.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=log_report)
        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
            check_consistent_augmented_stream=False,
        )

        expected_features = {
            "app_name": [FV("LogApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.log.app")],
            "file_name": [FV("log.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
        }

        debug_log_hash = DATA_HASH(log_report["debug"]["log"].encode()).hexdigest()
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256=DATA_HASH(data).hexdigest(),
                        data=[EventData(hash=debug_log_hash, label="text")],
                        features=expected_features,
                    )
                ],
                data={debug_log_hash: b""},
            ),
        )

    def test_empty_activities_list(self):
        empty_activities_report = {
            "app_name": "EmptyApp",
            "app_type": "android",
            "file_name": "empty.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.empty.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "activities": [],
            "exported_activities": [],
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "empty.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(
            method="POST", url="http://localhost/api/v1/report_json", json=empty_activities_report
        )
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("EmptyApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.empty.app")],
            "file_name": [FV("empty.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
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

    def test_empty_permissions(self):
        empty_perms_report = {
            "app_name": "NoPermsApp",
            "app_type": "android",
            "file_name": "noperms.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.noperms.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "permissions": {},
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "noperms.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=empty_perms_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("NoPermsApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.noperms.app")],
            "file_name": [FV("noperms.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
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

    def test_no_manifest_analysis(self):
        no_manifest_report = {
            "app_name": "NoManifestApp",
            "app_type": "android",
            "file_name": "nomanifest.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.nomanifest.app",
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
            json={"hash": file_hash, "scan_type": "apk", "file_name": "nomanifest.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=no_manifest_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("NoManifestApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.nomanifest.app")],
            "file_name": [FV("nomanifest.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
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

    def test_malware_permissions_only_top(self):
        top_only_report = {
            "app_name": "TopOnlyApp",
            "app_type": "android",
            "file_name": "toponly.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.toponly.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "malware_permissions": {
                "top_malware_permissions": ["android.permission.SEND_SMS", "android.permission.READ_SMS"]
            },
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "toponly.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=top_only_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("TopOnlyApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.toponly.app")],
            "file_name": [FV("toponly.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "min_version": [FV("21")],
            "malware_permissions": [
                FV("Top Malware: android.permission.READ_SMS"),
                FV("Top Malware: android.permission.SEND_SMS"),
            ],
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

    def test_network_security_and_domains(self):
        network_report = {
            "app_name": "NetworkApp",
            "app_type": "android",
            "file_name": "network.apk",
            "size": "3MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.network.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "network_security": {
                "network_findings": [
                    {"severity": "high", "description": "Allows cleartext traffic"},
                    {"severity": "warning", "description": "Weak cipher used"},
                ]
            },
            "domains": {
                "example.com": {"geolocation": {"country_long": "United States", "city": "New York"}, "ofac": False},
                "suspicious.io": {"geolocation": {"country_long": "Unknown", "city": "Unknown"}, "ofac": True},
            },
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "network.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=network_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("NetworkApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.network.app")],
            "domains": [
                FV("example.com (United States, New York) - Not OFAC Listed"),
                FV("suspicious.io (Unknown, Unknown) - OFAC Listed"),
            ],
            "file_name": [FV("network.apk")],
            "file_size": [FV("3MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "version_code": [FV("1")],
            "version_name": [FV("1.0")],
            "network_security": [FV("high: Allows cleartext traffic"), FV("warning: Weak cipher used")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_domains_with_none_geolocation(self):
        """Test that plugin handles domains where geolocation field is explicitly None."""
        report = {
            "app_name": "TestApp",
            "app_type": "android",
            "file_name": "test.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.test.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "domains": {
                "example.com": {"geolocation": None, "ofac": False},
                "test.io": {"geolocation": {"country_long": "Canada", "city": "Toronto"}, "ofac": False},
            },
        }

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
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("TestApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.test.app")],
            "domains": [
                FV("example.com (Unknown, Unknown) - Not OFAC Listed"),
                FV("test.io (Canada, Toronto) - Not OFAC Listed"),
            ],
            "file_name": [FV("test.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
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

    def test_certificate_findings_multiple(self):
        multi_cert_report = {
            "app_name": "MultiCertApp",
            "app_type": "android",
            "file_name": "multicert.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.multicert.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "certificate_analysis": {
                "certificate_findings": [
                    ["critical", "Expired certificate", "Certificate has expired"],
                    ["high", "Self-signed", "Certificate is self-signed"],
                    ["warning", "SHA1", "SHA1 algorithm is weak"],
                    ["info", "RSA 2048", "RSA key is adequate"],
                ]
            },
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "multicert.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=multi_cert_report)
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("MultiCertApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.multicert.app")],
            "file_name": [FV("multicert.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "version_name": [FV("1.0")],
            "version_code": [FV("1")],
            "min_version": [FV("21")],
            "target_version": [FV("30")],
            "certificate_analysis": [
                FV("critical: Expired certificate"),
                FV("high: Self-signed"),
                FV("warning: SHA1"),
                FV("info: RSA 2048"),
            ],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_multiple_manifest_findings(self):
        multi_findings_report = {
            "app_name": "MultiApp",
            "app_type": "android",
            "file_name": "multi.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.multi.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "manifest_analysis": {
                "manifest_findings": [
                    {"severity": "high", "title": "Issue1", "description": "Backup enabled"},
                    {"severity": "warning", "title": "Issue2", "description": "Debuggable enabled"},
                    {"severity": "info", "title": "Issue3", "description": "Info message"},
                ],
                "manifest_summary": {"high": 1, "warning": 1, "info": 1},
            },
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "multi.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(
            method="POST", url="http://localhost/api/v1/report_json", json=multi_findings_report
        )
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("MultiApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.multi.app")],
            "file_name": [FV("multi.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
            "manifest_findings": [
                FV("high: Issue1 - Backup enabled"),
                FV("info: Issue3 - Info message"),
                FV("warning: Issue2 - Debuggable enabled"),
            ],
            "manifest_summary": [FV("High: 1, Warning: 1, Info: 1")],
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

    def test_empty_malware_permissions(self):
        """Test malware_permissions with empty lists."""
        empty_malware_report = {
            "app_name": "EmptyMalwareApp",
            "app_type": "android",
            "file_name": "emptymalware.apk",
            "size": "1MB",
            "version_name": "1.0",
            "version_code": "1",
            "package_name": "com.emptymalware.app",
            "min_sdk": "21",
            "target_sdk": "30",
            "malware_permissions": {"top_malware_permissions": [], "other_abused_permissions": []},
        }

        data = make_fake_apk()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", status_code=404)
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan_logs", status_code=400)
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/upload",
            json={"hash": file_hash, "scan_type": "apk", "file_name": "emptymalware.apk"},
        )
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/scan", json={"status": "success"})
        self.httpx_mock.add_response(
            method="POST",
            url="http://localhost/api/v1/scan_logs",
            json={"logs": [{"timestamp": "2025-12-15 00:31:10", "status": "Saving to Database", "exception": None}]},
        )
        self.httpx_mock.add_response(
            method="POST", url="http://localhost/api/v1/report_json", json=empty_malware_report
        )
        result = self.do_execution(
            data_in=[("content", data)], config=self.PLUGIN_TO_TEST_CONFIG, no_multiprocessing=True
        )

        expected_features = {
            "app_name": [FV("EmptyMalwareApp")],
            "app_type": [FV("android")],
            "bundle_id": [FV("com.emptymalware.app")],
            "file_name": [FV("emptymalware.apk")],
            "file_size": [FV("1MB")],
            "mobsf_record_url": [FV(MOBSF_FAKE_APK_RECORD_URL)],
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
