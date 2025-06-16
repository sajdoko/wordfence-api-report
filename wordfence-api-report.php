<?php
  /**
   * Plugin Name:       Wordfence API Report
   * Plugin URI:        https://github.com/sajdoko/wordfence-api-report
   * Description:       Exposes key Wordfence security data via a secure REST API endpoint for external monitoring.
   * Version:           1.5.0
   * Author:            Sajmir Doko
   * Author URI:        https://localweb.it
   * Requires at least: 5.5
   * Requires PHP:      7.4
   * Requires Plugins:  wordfence
   * License:           GPL v2 or later
   * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
   * Text Domain:       wordfence-api-report
   */

  /*
    * ==========================================================================
    * HOW TO USE
    * ==========================================================================
    *
    * 1. Install and activate this plugin. Wordfence must be active first.
    * 2. Go to Settings -> Wordfence API Report in your WordPress admin area.
    * 3. Click the "Generate New Key" button to create and save your API key.
    * 4. Use this key in the 'X-Api-Key' header for your requests.
    *
    * ==========================================================================
    * ENDPOINT DETAILS
    * ==========================================================================
    *
    * Method: GET
    * URL:    /wp-json/wordfence/v1/report
    * Header: X-Api-Key: your-super-secret-key-here
    *
    * ==========================================================================
    */

  // Prevent direct script access for security.
  if (! defined('ABSPATH')) {
    exit;
  }

  /**
   * =========================================================================
   * Plugin Update Checker
   * =========================================================================
   *
   * This section includes the plugin update checker to manage updates from GitHub.
   */
  require_once plugin_dir_path(__FILE__) . 'plugin-update-checker/plugin-update-checker.php';
  use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

  $myUpdateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/sajdoko/wordfence-api-report/', // GitHub repo URL
    __FILE__,
    'wordfence-api-report'
  );

  // Optional: If your repo is private, set the access token
  // $myUpdateChecker->setAuthentication('your-github-token');

  // Optional: Set the branch to check for updates (default is 'master')
  $myUpdateChecker->setBranch('main');
  $myUpdateChecker->getVcsApi()->enableReleaseAssets();

  /**
   * =========================================================================
   * Activation & Dependency Check
   * =========================================================================
   */

  /**
   * The function that runs during plugin activation.
   * Checks if Wordfence is active, and if not, deactivates the plugin.
   */
  function wordfence_api_activate() {
    if (! function_exists('is_plugin_active')) {
      include_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    if (! is_plugin_active('wordfence/wordfence.php')) {
      deactivate_plugins(plugin_basename(__FILE__));
      wp_die(
        esc_html__('This plugin requires the Wordfence Security plugin to be installed and activated. Please install and activate Wordfence, then try again.', 'wordfence-api-report'),
        esc_html__('Plugin Activation Error', 'wordfence-api-report'),
        ['back_link' => true]
      );
    }
  }
  register_activation_hook(__FILE__, 'wordfence_api_activate');

  /**
   * =========================================================================
   * Admin Interface & Settings
   * =========================================================================
   */

  /**
   * Adds the options page as a submenu under the main Wordfence menu.
   */
  function wordfence_api_add_admin_menu() {
    add_submenu_page(
      'Wordfence',                      // Parent slug
      'Wordfence API Report',           // Page title
      'API Report',                     // Menu title
      'manage_options',                 // Capability
      'wordfence-api-report',           // Menu slug
      'wordfence_api_options_page_html' // Callback function
    );
  }
  add_action('admin_menu', 'wordfence_api_add_admin_menu', 99);

  /**
   * Initializes the settings, registers the setting, section, and fields.
   */
  function wordfence_api_settings_init() {
    // Register the setting
    register_setting('wordfence_api_page', 'wordfence_api_key');

    // Add the settings section
    add_settings_section(
      'wordfence_api_section',
      __('API Key Management', 'wordfence-api-report'),
      null,
      'wordfence_api_page'
    );

    // Add the API key field
    add_settings_field(
      'wordfence_api_key_field',
      __('Your API Key', 'wordfence-api-report'),
      'wordfence_api_key_field_callback',
      'wordfence_api_page',
      'wordfence_api_section'
    );
  }
  add_action('admin_init', 'wordfence_api_settings_init');

  /**
   * Renders the input field for the API Key.
   */
  function wordfence_api_key_field_callback() {
    $api_key = get_option('wordfence_api_key');

    // Create the URL for the "Generate New Key" action with a nonce.
    $generation_url = wp_nonce_url(
      admin_url('options-general.php?page=wordfence-api-report&action=generate_key'),
      'wordfence_generate_key_nonce',
      'wordfence_nonce'
    );

    echo '<input type="text" id="wordfence_api_key" name="wordfence_api_key" value="' . esc_attr($api_key) . '" readonly class="regular-text" />';
    echo '<a href="' . esc_url($generation_url) . '" class="button button-secondary" style="margin-left: 10px;">' . __('Generate New Key', 'wordfence-api-report') . '</a>';
    echo '<p class="description">' . __('Click "Generate New Key" to create a secure key. The key is saved automatically.', 'wordfence-api-report') . '</p>';
  }

  /**
   * Handles the key generation action.
   */
  function wordfence_api_handle_actions() {
    if (isset($_GET['action']) && $_GET['action'] === 'generate_key' && isset($_GET['wordfence_nonce'])) {
      if (wp_verify_nonce($_GET['wordfence_nonce'], 'wordfence_generate_key_nonce')) {
        // Generate a new secure API key (64 characters)
        $new_key = bin2hex(random_bytes(32));
        update_option('wordfence_api_key', $new_key);

        // Redirect back to the settings page with a success message
        wp_safe_redirect(admin_url('options-general.php?page=wordfence-api-report&key_generated=1'));
        exit;
      }
    }
  }
  add_action('admin_init', 'wordfence_api_handle_actions');

  /**
   * Displays an admin notice on successful key generation.
   */
  function wordfence_api_admin_notices() {
    if (isset($_GET['page']) && $_GET['page'] === 'wordfence-api-report' && isset($_GET['key_generated'])) {
      echo '<div class="notice notice-success is-dismissible"><p>' . __('New API key has been generated and saved successfully.', 'wordfence-api-report') . '</p></div>';
    }
  }
  add_action('admin_notices', 'wordfence_api_admin_notices');

  /**
   * Renders the main options page HTML structure.
   */
  function wordfence_api_options_page_html() {
    if (! current_user_can('manage_options')) {
      return;
    }
  ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <p><?php _e('Use this page to manage the secure API key for accessing Wordfence data externally.', 'wordfence-api-report'); ?></p>
        <form action="options.php" method="post">
            <?php
              settings_fields('wordfence_api_page');
                do_settings_sections('wordfence_api_page');
              ?>
        </form>
    </div>
    <?php
      }

      /**
       * =========================================================================
       * REST API Endpoint
       * =========================================================================
       */

      /**
       * Main initialization function for the API endpoint.
       */
      function wordfence_api_init() {
        if (! function_exists('is_plugin_active')) {
          require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (is_plugin_active('wordfence/wordfence.php')) {
          add_action('rest_api_init', 'wordfence_api_register_routes');
        }
      }
      add_action('plugins_loaded', 'wordfence_api_init');

      /**
       * Registers the custom REST API route.
       */
      function wordfence_api_register_routes() {
        register_rest_route(
          'wordfence/v1',
          '/report',
          [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => 'wordfence_api_get_report_data',
            'permission_callback' => 'wordfence_api_permission_check',
          ]
        );
      }

      /**
       * Permission callback to authenticate the API request.
       */
      function wordfence_api_permission_check(WP_REST_Request $request) {
        $stored_key  = get_option('wordfence_api_key');
        $request_key = $request->get_header('x_api_key');

        if (! $stored_key) {
          return new WP_Error(
            'rest_api_key_not_configured',
            'API key is not configured on this site.',
            ['status' => 500]
          );
        }

        if (empty($request_key) || ! hash_equals($stored_key, $request_key)) {
          return new WP_Error(
            'rest_forbidden',
            'Invalid or missing API Key.',
            ['status' => 403]
          );
        }

        return true;
      }

      /**
       * Helper function to determine the scan status.
       */
      function wordfence_api_get_scan_status($last_scan_time, $total_issues) {
        if (! $last_scan_time) {
          return 'Never scanned';
        }
        if ($total_issues > 0) {
          return 'Completed with issues';
        }
        return 'Completed without issues';
      }

      /**
       * Helper function to get top blocked IPs.
       */
      function wordfence_api_get_top_blocked_ips($limit = 5) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wfblockediplog';
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
          return [];
        }
        return $wpdb->get_results($wpdb->prepare(
          "SELECT ip, COUNT(*) as block_count FROM {$table_name} GROUP BY ip ORDER BY block_count DESC LIMIT %d",
          $limit
        ));
      }

      /**
       * Helper function to get top blocked countries.
       */
      function wordfence_api_get_top_blocked_countries($limit = 5) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wflivetraffic';
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
          return [];
        }
        return $wpdb->get_results($wpdb->prepare(
          "SELECT countryCode, COUNT(*) as block_count FROM {$table_name} WHERE action = 'blocked' AND countryCode != '' GROUP BY countryCode ORDER BY block_count DESC LIMIT %d",
          $limit
        ));
      }

      /**
       * Callback function to fetch and return the comprehensive Wordfence data.
       */
      function wordfence_api_get_report_data(WP_REST_Request $request) {
        if (! class_exists('wfIssues') || ! class_exists('wfConfig')) {
          return new WP_Error(
            'wordfence_unavailable',
            'Could not access Wordfence components.',
            ['status' => 503]
          );
        }

        // 1. Scan Results Summary
        $wf_issues     = new wfIssues();
        $issue_counts  = $wf_issues->getIssueCounts();
        $malware_count = isset($issue_counts['critical']) ? (int) $issue_counts['critical'] : 0;
        $warning_count = (isset($issue_counts['high']) ? (int) $issue_counts['high'] : 0) +
          (isset($issue_counts['medium']) ? (int) $issue_counts['medium'] : 0) +
          (isset($issue_counts['low']) ? (int) $issue_counts['low'] : 0);
        $total_issues        = $malware_count + $warning_count;
        $last_scan_timestamp = (int) get_option('wordfence_lastScanStart', 0);

        $scan_summary = [
          'last_scan_timestamp'      => $last_scan_timestamp,
          'status'                   => wordfence_api_get_scan_status($last_scan_timestamp, $total_issues),
          'total_issues_found'       => $total_issues,
          'issue_counts_by_severity' => [
            'malware'  => $malware_count,
            'warnings' => $warning_count,
          ],
        ];

        // 2. Threats Blocked & Firewall
        $threats_blocked = [
          'total_firewall_blocks' => (int) wfConfig::get('totalBlocked', 0),
          'brute_force_blocks'    => (int) wfConfig::get('bruteForceLoginAttemptsBlocked', 0),
          'top_blocked_ips'       => wordfence_api_get_top_blocked_ips(5),
          'top_blocked_countries' => wordfence_api_get_top_blocked_countries(5),
        ];

        // 3. Recommendations
        $recommendations = [
          'is_premium'               => (bool) wfConfig::get('isPaid'),
          'is_2fa_active'            => (bool) wfConfig::get('loginSec_requireAdminTwoFactor', false),
          'is_scheduled_scan_active' => (bool) wfConfig::get('scheduledScansEnabled'),
        ];

        // Assemble final payload
        $data = [
          'scan_summary'    => $scan_summary,
          'threats_blocked' => $threats_blocked,
          'recommendations' => $recommendations,
        ];

        return new WP_REST_Response($data, 200);
    }
