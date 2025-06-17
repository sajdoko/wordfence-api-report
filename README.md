# Wordfence API Report

Exposes advanced Wordfence security data via a secure REST API endpoint for external monitoring, dashboards, or integrations (e.g., Laravel CRM).

## Description
This plugin provides a REST API endpoint to retrieve detailed security metrics from the Wordfence plugin, including activity reports, top blocked IPs/countries, failed logins, and more. It is designed for integration with external monitoring systems and supports GitHub-based plugin updates.

## Features
- Secure REST API endpoint for Wordfence data
- Activity report with:
  - Top blocked IPs (with readable IP addresses)
  - Top blocked countries
  - Top failed login attempts
- Scan summary (status, issues, last scan time)
- Security recommendations (premium status, 2FA, scheduled scans)
- API key management from the Wordfence menu
- GitHub-based plugin update support (via Plugin Update Checker)

## Requirements
- WordPress 5.5 or higher
- PHP 7.4 or higher
- [Wordfence Security](https://wordpress.org/plugins/wordfence/) plugin must be installed and active

## Installation
1. Ensure Wordfence is installed and activated.
2. Upload this plugin to your `/wp-content/plugins/` directory.
3. Activate the plugin through the WordPress admin.
4. Go to **Wordfence → API Report** to generate and copy your API key.

## Usage
- **Endpoint:** `/wp-json/wordfence/v1/report`
- **Method:** `GET`
- **Header:** `X-Api-Key: your-super-secret-key-here`

Example request using `curl`:

```sh
curl -H "X-Api-Key: your-super-secret-key-here" https://yourdomain.com/wp-json/wordfence/v1/report
```

## Response Example

```json
{
  "getTopIPsBlocked": [
    { "IP": "192.0.2.1", "count": 12 },
    ...
  ],
  "getTopCountriesBlocked": [
    { "country": "US", "count": 34 },
    ...
  ],
  "getTopFailedLogins": [
    { "IP": "203.0.113.5", "username": "admin", "count": 7 },
    ...
  ],
  "scan_summary": {
    "last_scan_timestamp": 1750143959,
    "status": "Completed with issues",
    "total_issues_found": 3,
    "issue_counts_by_status": {
        "new": "3"
    },
    "issues": [...]
}
```

## Security
- Only requests with a valid API key (set in plugin settings) will receive data.
- Keep your API key secret and rotate it if needed.

## Changelog
### 1.5.0
- Added activity report endpoints (top IPs, countries, failed logins, readable IPs)
- Integrated with Wordfence's wfActivityReport for advanced reporting
- Improved API key management and admin UI
- GitHub-based plugin update support

### 1.4.0
- Improved error handling and compatibility
- Updated REST response structure

### 1.0.0
- Initial release

## License
GPL v2 or later

## Author
[Sajmir Doko](https://localweb.it)
