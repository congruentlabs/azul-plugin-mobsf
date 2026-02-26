"""Submit binaries to MobSF static analysis."""

import logging
import traceback

import httpx
from azul_bedrock.models_network import FeatureType
from azul_runner import (
    BinaryPlugin,
    Feature,
    Job,
    State,
    add_settings,
    cmdline_run,
)

from .mobsf import MobSF, MobSFError

(ftInt, ftFloat, ftStr) = (FeatureType.Integer, FeatureType.Float, FeatureType.String)
logger = logging.getLogger(__name__)


class AzulPluginMobSF(BinaryPlugin):
    """Submit binaries to MobSF static analysis."""

    VERSION = "2025.02.12"
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "android/apk",
                "ios/ipa",
            ]
        },
        run_timeout=20 * 60,  # MobSF runs can take a long time if the apps submitted are large.
        filter_max_content_size="512MiB",  # File size to process - you may need to configure Azul to allow larger files as well.
        request_timeout=30,  # How long to wait for the server before error
        # custom options
        start_timeout=(int, 10 * 60),  # Report error if MobSF doesn't start running the sample within this time
        mobsf_server=(str, ""),  # URL of the MobSF server, eg http://localhost:8000
        mobsf_auth_token=(str, ""),  # Token for server auth
        scanning_mode=(str, "STATIC"),  # STATIC or DYNAMIC
        poll_interval=(int, 15),  # Seconds to wait between polling of MobSF server for job status
        api_retry_count=(int, 3),  # How many times to retry API requests on timeout or temporary error
    )
    FEATURES = [
        # Basic app information
        Feature("app_name", desc="App Name", type=ftStr),
        Feature("app_type", desc="Type of application (apk, ipa)", type=ftStr),
        Feature("file_name", desc="File name submitted to MobSF", type=ftStr),
        Feature("file_size", desc="Size of the analyzed file", type=ftStr),
        # Version information
        Feature(
            "version_name", desc="Application version name", type=ftStr
        ),  # version_name for APK, version_name or app_version for IPA
        Feature("version_code", desc="Application version code", type=ftStr),  # version_code for APK, build for IPA
        # Package/Bundle information
        Feature("bundle_id", desc="App Bundle/Package ID", type=ftStr),  # package_name for APK, bundle_id for IPA
        # SDK/Platform information
        Feature(
            "min_version", desc="Minimum required platform version", type=ftStr
        ),  # min_sdk for APK, min_os_version for IPA
        Feature("target_version", desc="Target platform version", type=ftStr),  # target_sdk for APK, platform for IPA
        Feature("sdk_name", desc="SDK Name (iOS only)", type=ftStr),  # iOS only
        # Android-specific components (only populated for APKs)
        Feature("main_activity", desc="App Main Activity (Android only)", type=ftStr),
        Feature("activities", desc="List of all activities in the app (Android only)", type=ftStr),
        Feature(
            "exported_activities", desc="List of activities accessible from outside the app (Android only)", type=ftStr
        ),
        Feature("services", desc="List of services in the app (Android only)", type=ftStr),
        Feature("receivers", desc="List of broadcast receivers in the app (Android only)", type=ftStr),
        Feature("providers", desc="List of content providers in the app (Android only)", type=ftStr),
        # Permissions and security
        Feature("permissions", desc="Application Permissions", type=ftStr),
        Feature("malware_permissions", desc="Permissions commonly abused by malware", type=ftStr),
        # Certificate information
        Feature("certificate_analysis", desc="MobSF signing certificate vulnerabilities", type=ftStr),
        # Behavior and Tracking
        Feature("behaviour", desc="Application behavior analysis", type=ftStr),
        Feature("security_score", desc="Overall security score", type=ftInt),
        Feature("detected_trackers", desc="Number of trackers actually detected in the app", type=ftInt),
        Feature("total_trackers", desc="Total number of tracking libraries in MobSF database", type=ftInt),
        # Analysis findings
        Feature("manifest_findings", desc="Security issues found in manifest/info.plist analysis", type=ftStr),
        Feature("manifest_summary", desc="Summary of manifest analysis findings", type=ftStr),
        Feature("network_security", desc="Network security configuration findings", type=ftStr),
        Feature("domains", desc="Network domains accessed by the app", type=ftStr),
        Feature("secrets", desc="Sensitive information found in the app", type=ftStr),
        # Code analysis
        Feature("code_analysis", desc="Static code security findings with CVSS and CWE identifiers", type=ftStr),
        Feature("android_api", desc="Android API usage patterns detected in the application", type=ftStr),
        Feature("apkid", desc="APK compiler and manipulator detection (indicates repacking)", type=ftStr),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self.cfg.mobsf_server:
            raise RuntimeError("MobSF server URL must be set")
        if not httpx.URL(self.cfg.mobsf_server).is_absolute_url:
            raise RuntimeError(f"Unable to use MobSF server with URL '{self.cfg.mobsf_server}'")
        if not self.cfg.mobsf_auth_token:
            raise RuntimeError("MobSF authentication token must be set")

        # Convert configs to integers if they aren't (config from env is always strings)
        for cfg_var in (
            "start_timeout",
            "poll_interval",
            "api_retry_count",
        ):
            try:
                setattr(self.cfg, cfg_var, int(getattr(self.cfg, cfg_var)))
            except ValueError as e:
                raise ValueError(f"Config setting {cfg_var} must be an int value") from e

    def execute(self, job: Job):
        """Run the plugin."""
        try:
            return self.execute_body(job)
        except httpx.RequestError as exc:
            # RequestError covers everything that could be due to network state,  such as timeouts,
            #  connection failures and protocol errors, but not response-code errors (eg 404, 500 etc)
            return State(State.Label.ERROR_NETWORK, exc.args[0], "".join(traceback.format_exc()))
        except MobSFError as exc:
            return State(State.Label.ERROR_EXCEPTION, exc.args[0], exc.mobsf_message)

    def execute_body(self, job: Job):
        """Main body of the plugin run, wrapped by a network exception handler in execute()."""
        mobsf = MobSF(self.cfg)
        mobsf_task, is_complete = mobsf.find_or_submit(job)

        # If scan is not complete, wait for it
        if not is_complete:
            logger.info("Waiting for MobSF scan to complete...")
            mobsf.wait_for_completion(mobsf_task)
            mobsf_report = mobsf.fetch_job_report(mobsf_task)
        else:
            # Scan already complete, mobsf_task contains the report
            logger.info("Using existing scan results")
            mobsf_report = mobsf_task

        self.add_feature_values("app_name", [mobsf_report.get("app_name", "")])
        self.add_feature_values("app_type", [mobsf_report.get("app_type", "")])
        self.add_feature_values("file_name", [mobsf_report.get("file_name", "")])
        self.add_feature_values("file_size", [mobsf_report.get("size", "")])

        # Version information - platform specific
        if mobsf_report.get("app_type", "").lower() == "swift":
            # iOS version handling
            self.add_feature_values("version_name", [mobsf_report.get("app_version", "")])
            self.add_feature_values("version_code", [mobsf_report.get("build", "")])

            # iOS bundle and SDK info
            self.add_feature_values("bundle_id", [mobsf_report.get("bundle_id", "")])
            self.add_feature_values("min_version", [mobsf_report.get("min_os_version", "")])
            self.add_feature_values("target_version", [mobsf_report.get("platform", "")])
            self.add_feature_values("sdk_name", [mobsf_report.get("sdk_name", "")])
        else:
            # Android version handling
            self.add_feature_values("version_name", [mobsf_report.get("version_name", "")])
            self.add_feature_values("version_code", [mobsf_report.get("version_code", "")])

            # Android package and SDK info
            self.add_feature_values("bundle_id", [mobsf_report.get("package_name", "")])
            self.add_feature_values("min_version", [mobsf_report.get("min_sdk", "")])
            self.add_feature_values("target_version", [mobsf_report.get("target_sdk", "")])

            # Android-specific components
            if mobsf_report.get("main_activity"):
                self.add_feature_values("main_activity", [mobsf_report["main_activity"]])
            if "activities" in mobsf_report:
                self.add_feature_values("activities", mobsf_report["activities"])

        # Extract exported activities (handle both string and list formats)
        exported = mobsf_report.get("exported_activities", "[]")
        if isinstance(exported, str):
            # Clean up string representation of list
            exported = exported.strip("[]").replace("'", "").split(", ")
        elif not isinstance(exported, list):
            exported = []
        self.add_feature_values("exported_activities", [a for a in exported if a])

        # Extract permissions - platform specific
        perm_details = []
        if mobsf_report.get("app_type", "").lower() == "swift":
            # iOS permissions from findings
            if "findings" in mobsf_report:
                for finding in mobsf_report["findings"]:
                    if finding.get("section") == "permissions":
                        perm_details.append(finding["description"])
        else:
            # Android permissions
            if "permissions" in mobsf_report:
                for perm_name, perm_info in mobsf_report["permissions"].items():
                    if isinstance(perm_info, dict):
                        status = perm_info.get("status", "unknown")
                        info = perm_info.get("info", "")
                        desc = perm_info.get("description", "")
                        perm_details.append(f"{perm_name} ({status}): {info} - {desc}")
                    else:
                        perm_details.append(perm_name)

        if perm_details:
            self.add_feature_values("permissions", perm_details)

        # Extract malware related permissions (Android only)
        if "malware_permissions" in mobsf_report:
            mal_perms = mobsf_report["malware_permissions"]
            mal_perm_details = []

            if "top_malware_permissions" in mal_perms:
                mal_perm_details.extend([f"Top Malware: {p}" for p in mal_perms["top_malware_permissions"]])
            if "other_abused_permissions" in mal_perms:
                mal_perm_details.extend([f"Abused: {p}" for p in mal_perms["other_abused_permissions"]])

            self.add_feature_values("malware_permissions", mal_perm_details)

        # Certificate analysis
        if "certificate_analysis" in mobsf_report:
            cert_data = mobsf_report["certificate_analysis"]
            cert_findings = []

            if "certificate_findings" in cert_data:
                for finding in cert_data["certificate_findings"]:
                    # Handle both tuple/list format - typically [severity, desc, detail]
                    if isinstance(finding, (list, tuple)) and len(finding) >= 2:
                        severity = finding[0]
                        desc = finding[1]
                        cert_findings.append(f"{severity}: {desc}")

            self.add_feature_values("certificate_analysis", cert_findings)

        # Extract manifest/info.plist analysis findings
        findings = []

        if mobsf_report.get("app_type", "").lower() == "swift":
            # iOS findings
            if "findings" in mobsf_report:
                for finding in mobsf_report["findings"]:
                    if finding.get("section") != "permissions":  # Skip permissions as they're handled separately
                        findings.append(f"{finding.get('title', '')}: {finding.get('description', '')}")
                if findings:
                    self.add_feature_values("manifest_findings", findings)
        else:
            # Android manifest findings
            if "manifest_analysis" in mobsf_report:
                manifest_data = mobsf_report["manifest_analysis"]
                if "manifest_findings" in manifest_data:
                    for finding in manifest_data["manifest_findings"]:
                        severity = finding.get("severity", "unknown")
                        title = finding.get("title", "").replace("<br>", " ")
                        description = finding.get("description", "")
                        if description:
                            findings.append(f"{severity}: {title} - {description}")
                        else:
                            findings.append(f"{severity}: {title}")
                    self.add_feature_values("manifest_findings", findings)

                if "manifest_summary" in manifest_data:
                    summary = manifest_data["manifest_summary"]
                    high = summary.get("high", 0)
                    warning = summary.get("warning", 0)
                    info = summary.get("info", 0)
                    summary_text = [f"High: {high}, Warning: {warning}, Info: {info}"]
                    self.add_feature_values("manifest_summary", summary_text)

        # Network security analysis
        if "network_security" in mobsf_report:
            net_sec = mobsf_report["network_security"]
            if "network_findings" in net_sec:
                findings = []
                for finding in net_sec["network_findings"]:
                    findings.append(f"{finding['severity']}: {finding['description']}")
                self.add_feature_values("network_security", findings)

        # Domain analysis
        if "domains" in mobsf_report:
            domain_info = []
            for domain, info in mobsf_report["domains"].items():
                geo = info.get("geolocation") or {}
                location = f"{geo.get('country_long', 'Unknown')}, {geo.get('city', 'Unknown')}"
                ofac = "OFAC Listed" if info.get("ofac") else "Not OFAC Listed"
                domain_info.append(f"{domain} ({location}) - {ofac}")
            self.add_feature_values("domains", domain_info)

        # Behavior analysis
        if "behaviour" in mobsf_report:
            behavior_info = []
            for category, behaviors in mobsf_report["behaviour"].items():
                for behavior in behaviors:
                    behavior_info.append(f"{category}: {behavior}")
            self.add_feature_values("behaviour", behavior_info)

        # Extract secrets
        if "secrets" in mobsf_report:
            self.add_feature_values("secrets", mobsf_report["secrets"])

        # Extract security score
        if "security_score" in mobsf_report:
            self.add_feature_values("security_score", [mobsf_report["security_score"]])

        # Code analysis findings (Android static analysis)
        if "code_analysis" in mobsf_report:
            code_data = mobsf_report["code_analysis"]
            if "findings" in code_data:
                code_findings = []
                for finding_id, finding_data in code_data["findings"].items():
                    if "metadata" in finding_data:
                        metadata = finding_data["metadata"]
                        severity = metadata.get("severity", "unknown")
                        desc = metadata.get("description", finding_id)
                        # Include CVSS and CWE if available
                        details = []
                        if "cvss" in metadata:
                            details.append(f"CVSS: {metadata['cvss']}")
                        if "cwe" in metadata:
                            details.append(metadata["cwe"])
                        if details:
                            code_findings.append(f"{severity}: {desc} ({', '.join(details)})")
                        else:
                            code_findings.append(f"{severity}: {desc}")
                if code_findings:
                    self.add_feature_values("code_analysis", code_findings)

        # Android API usage
        if "android_api" in mobsf_report:
            api_data = mobsf_report["android_api"]
            api_findings = []
            for api_name, api_info in api_data.items():
                if isinstance(api_info, dict) and "metadata" in api_info:
                    metadata = api_info["metadata"]
                    desc = metadata.get("description", api_name)
                    severity = metadata.get("severity", "info")
                    # Count number of files where this API is used
                    file_count = len(api_info.get("files", {}))
                    api_findings.append(f"{severity}: {desc} (used in {file_count} files)")
            if api_findings:
                self.add_feature_values("android_api", api_findings)

        # APKiD analysis - compiler and manipulator detection
        if "apkid" in mobsf_report:
            apkid_data = mobsf_report["apkid"]
            apkid_findings = []
            for dex_file, detection_info in apkid_data.items():
                if isinstance(detection_info, dict):
                    # Extract compiler info
                    if "compiler" in detection_info:
                        compilers = detection_info["compiler"]
                        if compilers:
                            apkid_findings.append(f"{dex_file} - Compiler: {', '.join(compilers)}")
                    # Extract manipulator info (indicates tampering/repacking)
                    if "manipulator" in detection_info:
                        manipulators = detection_info["manipulator"]
                        if manipulators:
                            apkid_findings.append(f"{dex_file} - Manipulator: {', '.join(manipulators)}")
            if apkid_findings:
                self.add_feature_values("apkid", apkid_findings)

        # Extract tracker information
        if "trackers" in mobsf_report:
            trackers = mobsf_report["trackers"]
            if "detected_trackers" in trackers:
                self.add_feature_values("detected_trackers", [trackers["detected_trackers"]])
            if "total_trackers" in trackers:
                self.add_feature_values("total_trackers", [trackers["total_trackers"]])

        # Add MobSF's execution log as a text artifact, if non-null
        if (mobsf_report.get("debug") or {}).get("log"):
            self.add_text(mobsf_report["debug"]["log"])

        return State(State.Label.COMPLETED)


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginMobSF)


if __name__ == "__main__":
    main()
