from azul_runner import DATA_HASH, FV, Event, JobResult, State

from .common import MOBSF_FAKE_APK_RECORD_URL, BaseMobSFTest, make_fake_apk


class TestExistingReport(BaseMobSFTest):
    def test_existing_report_handling(self):
        """Test that when MobSF already has a report, we use it directly without uploading."""
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
        }

        data = make_fake_apk()

        # Mock: MobSF already has this report, so return it immediately (200 OK, not 404)
        # This means no upload or scan calls should happen
        self.httpx_mock.add_response(method="POST", url="http://localhost/api/v1/report_json", json=dummy_apk_report)

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
            "version_name": [FV("1.0.0")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )
