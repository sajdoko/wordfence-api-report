# Wordfence API Report

Exposes key Wordfence security data via a secure REST API endpoint for external monitoring, such as in a Laravel CRM.

## Description
This plugin provides a REST API endpoint to retrieve important security metrics from the Wordfence plugin, including scan results, threats blocked, and security recommendations. It is designed for integration with external monitoring systems.

## Features
- Secure REST API endpoint for Wordfence data
- Scan summary (malware, warnings, last scan time)
- Threats blocked (firewall, brute force, top IPs/countries)
- Security recommendations (premium status, 2FA, scheduled scans)

## Requirements
- WordPress 5.5 or higher
- PHP 7.4 or higher
- [Wordfence Security](https://wordpress.org/plugins/wordfence/) plugin must be installed and active

## Installation
1. Ensure Wordfence is installed and activated.
2. Upload this plugin to your `/wp-content/plugins/` directory.
3. Activate the plugin through the WordPress admin.
4. Go to **Settings → Wordfence API Report** to generate and copy your API key.

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
  "scan_summary": {
    "last_scan_timestamp": 1718500000,
    "status": "Completed without issues",
    "total_issues_found": 0,
    "issue_counts_by_severity": {
      "malware": 0,
      "warnings": 0
    }
  },
  "threats_blocked": {
    "total_firewall_blocks": 123,
    "brute_force_blocks": 45,
    "top_blocked_ips": [ ... ],
    "top_blocked_countries": [ ... ]
  },
  "recommendations": {
    "is_premium": false,
    "is_2fa_active": true,
    "is_scheduled_scan_active": true
  }
}
```

## Security
- Only requests with a valid API key (set in plugin settings) will receive data.
- Keep your API key secret and rotate it if needed.

## Changelog
### 1.4.0
- Improved error handling and compatibility
- Updated REST response structure

### 1.0.0
- Initial release

## License
GPL v2 or later

## Author
[Sajmir Doko](https://localweb.it)
