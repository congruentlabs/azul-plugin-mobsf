import json
from pathlib import Path

import pytest
from azul_runner import test_template

from azul_plugin_mobsf.main import AzulPluginMobSF


# The sample json reports are from actual malicious binaries that have been uploaded into mobsf, and the reports pulled via
def load_test_data(filename):
    """Load JSON test data from tests/unit/data directory."""
    data_dir = Path(__file__).parent / "data"
    with open(data_dir / filename, "r") as f:
        return json.load(f)


# The IPA & APK files for test invocation are contain just the minimum required to pass a magic bytes
# test for the plugin to accept them. They're only designed to get past the config check, and the tests
# mock the actual HTTP responses from MobSF.
def load_test_file(filename):
    """Load a test file from tests/unit/data directory."""
    data_dir = Path(__file__).parent / "data"
    with open(data_dir / filename, "rb") as f:
        return f.read()


def make_fake_apk():
    """Load sample.apk test file."""
    return load_test_file("sample.apk")


def make_fake_ipa():
    """Load sample.ipa test file."""
    return load_test_file("sample.ipa")


class BaseMobSFTest(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMobSF
    PLUGIN_TO_TEST_CONFIG = {
        "mobsf_server": "http://localhost",
        "mobsf_auth_token": "test_token",
        "request_timeout": 5,
        "api_retry_count": 2,
        "start_timeout": 10,
        "poll_interval": 1,  # Fast polling for tests (default is 15s)
        "filter_data_types": {
            "content": [
                "android/apk",
                "ios/ipa",
            ]
        },
    }

    @pytest.fixture(autouse=True)
    def _httpx_mock_fixture(self, httpx_mock):
        # Store mock for test use
        self.httpx_mock = httpx_mock
        return httpx_mock
