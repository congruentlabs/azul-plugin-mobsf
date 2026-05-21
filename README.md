# MobSF Plugin

Plugin for analyzing mobile applications using MobSF.

## Features

- Analyzes Android APK and iOS IPA files
- Extracts application metadata and security findings
- Integrates with MobSF REST API

## Configuration

Required configuration:
- `mobsf_server`: MobSF server URL
- `mobsf_auth_token`: API authentication token

Optional configuration:
- `request_timeout`: HTTP request timeout (default: 30)
- `api_retry_count`: Number of retries on API errors (default: 3)
- `start_timeout`: Maximum time to wait for scan to complete (default: 600)
- `poll_interval`: Polling interval for task status (default: 15)
