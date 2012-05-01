<?php
/* 
Plugin Name: Login Lock
Plugin URI: https://wpsecurity.net/wordpress-security-login-lock/
Version: v2.2.7
Author: Mark Edwards / WPSecurity.net 
Author URI: https://wpsecurity.net
Description: Enforces strong password policies, monitors login attempts, blocks IP address for too many failed login attempts.
*/

/*====================================================================

License: GPL v2

Copyright (c) 2009-2011 - Mark Edwards, https://wpsecurity.net

Minor portions, as labeled below, Copyright (c) 2007-2009, Michael VanDeMar

Some portions of this code, as labeled below, are extracted from 
core WordPress code. Those portions are copyright of their respective owners.


======================================================================*/


define( 'WPSEC_LOGINLOCK_VERSION', '2.2.4' );
define( 'WPSEC_LOGINLOCK_DB_VERSION', '2.0' );
define( 'WPSEC_LOGINLOCK_URL', plugin_dir_url(__FILE__) );

class LoginLock { 

	var $ll_options;
	var $fail_table;
	var $lock_table;

	function __construct() { 
		global $wpdb;

		$this->get_opts();

		$this->fail_table = $wpdb->prefix . 'login_fails';
		$this->lock_table = $wpdb->prefix . 'lockdowns';

		if(!defined('WP_PLUGIN_DIR'))
			define('WP_PLUGIN_DIR', ABSPATH . 'wp-content/plugins');

		register_activation_hook( __FILE__, array(&$this, 'll_install') );
		register_deactivation_hook(__FILE__, array( &$this, 'loginlock_uninstall') );
		add_action('admin_menu', array( &$this, 'add_page') );
		add_action('login_form', array( &$this, 'login_lock_notice' ) );
		add_filter('authenticate', array( &$this, 'll_wp_authenticate'), 21, 3);
		add_action('admin_enqueue_scripts', array( &$this, 'll_styles') );
		add_action('admin_notices', array( &$this, 'login_notice_show') );
		add_action('shutdown', array(&$this, 'login_notice_check') );
		add_action('admin_init', array( &$this, 'll_init') );
		add_action('init', array( &$this, 'll_base_init'), 9999999 );
		add_action('wp_login', array( &$this, 'll_update_login_timestamp'), 1 );
		add_action('get_header', array( &$this, 'll_check_active_time'), 1 );
		add_action('init', array( &$this, 'll_check_active_time'), 1 );
		add_action('show_user_profile', array( &$this, 'll_show_policy_notices') , -1, 1);
		add_action('edit_user_profile', array( &$this, 'll_show_policy_notices'), -1, 1);
		add_action('user_profile_update_errors', array( &$this, 'll_psw_error_hook'), 999999999, 3 );
		add_action('check_passwords', array( &$this, 'll_check_psw_strength_hook') , 1, 3 );
		add_action('edit_user_profile_update', array( &$this, 'll_check_psw_strength_hook') , 1, 3 );
		add_action('personal_options_update', array( &$this, 'll_check_psw_strength_hook') , 1, 3 );
		add_action('password_reset', array( &$this, 'save_psw_hash' ), 5, 2);
		add_action('plugins_loaded' , array( &$this, 'check_force_psw_reset') );
		add_action( 'wp_ajax_ll_notice_hide', array( &$this, 'llajax_submit') );


		if (is_admin()) { 
			global $csa;
			require_once( dirname(__FILE__) . '/plugin_tools.php');
			$csa = new Custom_Plugin_Admin();
			add_action( 'wp_dashboard_setup', array($csa,'widget_setup') );        
			add_action( 'wp_network_dashboard_setup', array($csa,'widget_setup') ); 
			add_filter( 'wp_dashboard_widgets', array($csa, 'widget_order'), 9999999 );
			add_filter( 'wp_network_dashboard_widgets', array($csa, 'widget_order'), 9999999);
		}
	}


	function LoginLock() { 
		__construct();
	}


	// Michael VanDeMar
	// Use the same table structure as Login LockDown so IF people switch, 
	// then their data is preserved and used
	function ll_install() {
		global $wpdb;

		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

		if( $wpdb->get_var("SHOW TABLES LIKE '".$this->fail_table."'") != $this->fail_table ) {

			$sql = "CREATE TABLE " . $this->fail_table . " (
				`login_attempt_ID` bigint(20) NOT NULL AUTO_INCREMENT,
				`user_id` bigint(20) NOT NULL,
				`login_attempt_date` datetime NOT NULL default '0000-00-00 00:00:00',
				`login_attempt_IP` varchar(100) NOT NULL default '',
				PRIMARY KEY  (`login_attempt_ID`)
				);";

			dbDelta($sql);

			if ($wpdb->last_error)
				die($wpdb->last_error);

			add_option("loginlock_table1_version", WPSEC_LOGINLOCK_DB_VERSION);
		}

		if( $wpdb->get_var("SHOW TABLES LIKE '".$this->lock_table."'") != $this->lock_table ) {
			$sql = "CREATE TABLE " . $this->lock_table . " (
				`lockdown_ID` bigint(20) NOT NULL AUTO_INCREMENT,
				`user_id` bigint(20) NOT NULL,
				`lockdown_date` datetime NOT NULL default '0000-00-00 00:00:00',
				`release_date` datetime NOT NULL default '0000-00-00 00:00:00',
				`lockdown_IP` varchar(100) NOT NULL default '',
				PRIMARY KEY  (`lockdown_ID`)
				);";

			dbDelta($sql);

			if ($wpdb->last_error)
				die($wpdb->last_error);

			add_option("loginlock_table2_version", WPSEC_LOGINLOCK_DB_VERSION);
		}

		$this->get_opts();

		update_option('llp_options', $this->ll_options);

		$this->set_user_password_expirations();

		$this->save_current_hashes();

		if ( !wp_next_scheduled('loginlock_event') ) 
			wp_schedule_event( time(), 'hourly', 'loginlock_event' );

	}


	function loginlock_uninstall() {
		wp_clear_scheduled_hook('loginlock_event');
	}


	function ll_get_defaults() { 

		$opts = array(
			'max_login_retries' => 5,
			'retries_within' => 30,
			'lockout_length' => 60,
			'notify_admins' => 'yes',
			'force_psw_changes' => 'yes',
			'psw_change_days' => 30, 
			'psw_length' => 12, 
			'psw_policy' => 'high', 
			'psw_reuse' => 'yes',
			'idle_timer' => 15
		);

		return $opts;

	}


	function get_opts() {
		$defaults = $this->ll_get_defaults();
		$this->ll_options = get_option('llp_options');
		if ( !is_array($this->ll_options) ) $this->ll_options = array();
		if ( is_array($defaults) && is_array($this->ll_options) ) 
			$this->ll_options = array_merge( $defaults, $this->ll_options );
		if ( count( $this->ll_options ) <= 0 )
			$this->ll_options = $defaults;
		return;
	}


	function ll_init(){
		global $user_ID;


		//echo date('m-d-y H:i:s', time()). ' -> '. strtotime('April 29, 2011 16:36:00'). ' --> <br/>';
		//wp_reschedule_event( strtotime('April 29, 2011 16:37:00') , 'hourly', 'loginlock_event');
		//var_dump( date( 'm-d-y H:i:s' , wp_next_scheduled( 'loginlock_event'))); echo ' -- >'.time();

		//	$this->login_notice_check();
		//var_dump( date( 'm-d-y H:i:s' , wp_next_scheduled( 'loginlock_event'))); echo ' -- >'.time(); 

		register_setting( 'llp_options', 'llp_options', array( &$this, 'llp_validate') );
		if ( count($_GET) <= 0 ) return;
		if ( isset($_GET['login_notice_show']) && '0' == $_GET['login_notice_show'] )
			update_user_meta($user_ID, 'login_notice_show', false);
	}


	function ll_base_init() { 

		remove_filter('authenticate', 'wp_authenticate', 20, 3);
		remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

		if ( !isset($_GET) || empty($_GET) || !isset($_GET['action']) ) return;

		if ( $_GET['action'] == 'resetpass' ||  $_GET['action'] == 'rp'   ) { 
			if ( '' != $_GET['key'] && '' != $_GET['login'] ) { 
				$this->ll_reset_psw( $_GET['key'], $_GET['login'] );
				exit;
			} else { 
				wp_die('Seems as though there was an error. Hmmm.', 'Error');

			}
		}
	}


	function get_user_ip() {
		$ra = trim( $_SERVER["REMOTE_ADDR"] );
		if ( '' == $ra ) $ra = '127.0.0.1'; 
		return $ra; 
	}


	// Michael VanDeMar
	function count_failed($username = "") {
		global $wpdb;

		$ip = $this->get_user_ip();

		$class_c = substr ($ip, 0 , strrpos ( $ip, "." ));

		if (!$this->ll_options) 
			$this->ll_options = $this->get_opts();

		$sql = "select count(login_attempt_ID) FROM " . $this->fail_table . " where login_attempt_date + INTERVAL " .
			$this->ll_options['retries_within'] . " MINUTE > now() and " . 
			"login_attempt_IP like '" . $wpdb->escape($class_c) . "%'";

		$res = $wpdb->get_var( $sql );

		return $res;
	}

	// Michael VanDeMar / Mark Edwards
	function increment_failed($username = "") {
		global $wpdb;

		$ip = $this->get_user_ip();

		$username = sanitize_user($username);

		$user = get_user_by( 'login', $username );

		if ( !$user ) { 
			$user = new stdClass();
			$user->ID = 0;
		}

		$sql = "insert into " . $this->fail_table . " (user_id, login_attempt_date, login_attempt_IP) " .
			"values ('" . $user->ID . "', now(), '" . $wpdb->escape($ip) . "')";

		$wpdb->query($sql);

	}

	// Michael VanDeMar / Mark Edwards
	function lockout($username = "") {
		global $wpdb;

		$ip = $this->get_user_ip();;

		$username = sanitize_user($username);

		$user = get_user_by( 'login', $username );

		if ( !$user ) { 
			$user = new stdClass();
			$user->ID = 0;
		}

		$sql = "insert into " . $this->lock_table . " (user_id, lockdown_date, release_date, lockdown_IP) " .
			    "values ('" . $user->ID . "', NOW(), date_add( NOW(), interval " .
			    $this->ll_options['lockout_length'] . " MINUTE), '" . $wpdb->escape($ip) . "')";

		$wpdb->query($sql);

		if ( 'yes' == $this->ll_options['notify_admins'] )
			$this->ll_notify_admins( $ip, $username );

	}


	// Michael VanDeMar
	function is_locked_out() {
		global $wpdb;

		$ip = $this->get_user_ip();

		$class_c = substr ($ip, 0 , strrpos ( $ip, "." ));

		$sql = "select user_id from " . $this->lock_table .
			" where release_date > now() AND " . 
			"lockdown_IP like  '". $wpdb->escape($class_c) . "%'";

		$locked = $wpdb->get_var($sql);

		return $locked;
	}

	// Michael VanDeMar
	function list_locks() {
		global $wpdb;

		$sql = "select lockdown_ID, floor((UNIX_TIMESTAMP(release_date)-UNIX_TIMESTAMP(now()))/60) as minutes_left, ".
			"lockdown_IP from ". $this->lock_table ." where release_date > now()";

		$locks = $wpdb->get_results( $sql, ARRAY_A );

		return $locks;
	}

	function ll_get_all_admin_emails() { 
		global $wpdb;

		$admins = array();

		$sql = 'select ID, user_email from '.$wpdb->users;
		$res = $wpdb->get_results($sql, ARRAY_A);

		foreach($res as $u) { 
			if ( user_can ( $u['ID'], 'administrator' ) )
				$admins[] = $u['user_email'];
		}

		return $admins;

	}

	function ll_notify_admins( $ip, $username = '' ) { 


		$admins = $this->ll_get_all_admin_emails(); 

		if (!$admins) return;

		if ( is_multisite() )
			$blogname = $GLOBALS['current_site']->site_name;
		else
			$blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

		$title = __('SECURITY ALERT: Lockout Notice');

		$message = __('This notice is to inform you that someone at IP address');
		$message .= ' ' .$ip . ' ';
		$message .= __('tried to login to your site');
		$message .= ' "' . $blogname . '" ';
		$message .= __('and failed.') . "\n\n";

		$message .= __('The targeted username was');
		$message .= ' ' . $username . "\n\n";

		$message .= __('The IP address has been blocked for ');
		$message .= $this->ll_options['lockout_length'];
		$message .= __('minutes.') . "\n\n";

		foreach( $admins as $admin ) { 
			wp_mail($admin, $title, $message);
		}
	}




	// set initial timestamp for last password change
	function set_user_password_expirations() { 
		global $wpdb;

		$sql = 'select ID from '.$wpdb->users;

		$res = $wpdb->get_results($sql, ARRAY_A);

		if (!$res) return; // this condition would be weird eh? 

		foreach ($res[0] as $u) { 
			$d = get_user_meta( $u, 'll_password_changed_date', true);
			if ('' == $d) 
			    update_user_meta( $u, 'll_password_changed_date', time() );
		}

	}


	// this only saves hashes, not cleartext psws!
	function save_current_hashes() { 
		global $wpdb;

		$sql = 'select ID, user_pass from '.$wpdb->users;

		$res = $wpdb->get_results($sql, ARRAY_A);

		if (!$res) return; // this condition would be weird eh? 

		foreach ($res as $u) { 
			$oh = get_user_meta( $u['ID'], 'll_old_hashes', true);
			$oh[] = $u['user_pass'];
			$c = count($oh); 
			if (  $c > 5 ) { 
				$removed = array_splice($oh, 0, ($c - 5) );
			}
			update_user_meta( $u, 'll_old_hashes', $oh );
		}

	}



	// save one hash for the user whose profile is being changed or whose password is being updated
	function save_psw_hash( $user, $pass = '' ) { 
		global $wpdb;

		if ( !isset($user->ID) ) return;

		if ( !isset( $user->user_pass ) ) return;

		$oh = get_user_meta( $user->ID, 'll_old_hashes', true);

		$oh[] = wp_hash_password( $user->user_pass ); // cleartext, so hash it

		$c = count($oh); 

		if (  $c > 5 ) { 
			$removed = array_splice($oh, 0, ($c - 5) );
		}

		update_user_meta( $user->ID, 'll_old_hashes', $oh );
                update_user_meta( $user->ID, 'll_password_changed_date', time() );

	}


	// check for reuse
	function ll_test_new_psw( $pass, $login ) { 
		global $wpdb;

		if ( 'yes' != $this->ll_options['psw_reuse'] ) return; // feature is disabled

		$sql = 'select ID from '.$wpdb->users.' where user_login = "'.$login.'"';
		$uid = $wpdb->get_var($sql);

		if (!$uid) return true;  //  just return, this func runs when adding new users too. 

		$oh = get_user_meta( $uid, 'll_old_hashes', true);

		if ( !is_array($oh) ) return true; // should not happen unless someone deletes the meta key

		for ($i=0; $i < count($oh); $i++) { 
			if ( wp_check_password( $pass, $oh[$i] ) ) {
				return __('You cannot reuse old passwords! Choose a different password.');
			}
		}

		return true;

	}

	// set a flag that forces users to change their password immediately
	function force_user_password_change_now() { 
		global $wpdb;

		$sql = 'select ID, user_login, user_email  from '.$wpdb->users;

		$res = $wpdb->get_results($sql, ARRAY_A);

		if (!$res) return; // this condition would be weird eh? 

		$msgs = array();

		foreach ( $res as $u ) { 

			$rand_psw = wp_hash_password( wp_generate_password(16) );
			wp_set_password( $rand_psw, $u['ID'] );
			update_user_meta( $u, 'll_force_password_change_now', 1 );

			// Generate something random for a key...
			$key = wp_generate_password(20, false);
			do_action('retrieve_password_key', $u['user_login'], $key);
			// Now insert the new md5 key into the db
			$wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_login' => $u['user_login']));

			$res = $this->ll_alert_user( $u['user_login'], $u['user_email'], $key );

			if ( '' != $res )  
			    $msgs[] = $res; 
		}

		return $msgs; 

	}


	// based in part on core WordPress core
	function ll_alert_user( $user_login, $user_email, $key ) { 

		if ( is_multisite() )
			$blogname = $GLOBALS['current_site']->site_name;
		else
			$blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

		$message = __('ALERT: The admin of ' . $blogname . ' requires that you reset the password for the following account:') . "\r\n\r\n";
		$message .= network_site_url() . "\r\n\r\n";
		$message .= sprintf(__('Username: %s'), $user_login) . "\r\n\r\n";
		$message .= __('You must reset your password before you can log back in. To reset your password, visit the following address:') . "\r\n\r\n";
		$message .= '<' . network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user_login), 'login') . ">\r\n";

		$title = sprintf( __('[%s] Emergency Password Reset'), $blogname );

		$title = apply_filters('retrieve_password_title', $title);
		$message = apply_filters('retrieve_password_message', $message, $key);

		if ( $message && !wp_mail($user_email, $title, $message) )
			return  __('The e-mail could not be sent to '. $user_login ) . "<br />\n" . __('Possible reason: your host may have disabled the mail() function.');

	}


	function check_force_psw_reset() { 
		global $wpdb, $current_user;

		get_currentuserinfo();

		if (!$current_user) return;

		if (!$current_user->data) return;

		if ( !$this->ll_options ) return;

		$day = 60 * 60 * 24; 

		$id = $current_user->data->ID;

		if ( strpos( $_SERVER['REQUEST_URI'], 'wp-login.php') !== false ) 
			return;

		// force a change now? 
		if ( '1' == get_user_meta($id, 'll_force_password_change_now', true) ) {
		    $this->ll_login_header();
		    echo '<p style="color:#cf0000">'. __('An administrator has logged you out and you <em>must</em> reset your password before you can log back in.') . '</p>';
		    echo '<p style="margin-top: 12px">'. __('Check your email for a password reset notice.') . '</p>';	   
		    echo '<p style="margin-top: 12px">'. __('If after 10 minutes you do not have the notice then go to the login page, click the "Lost your password" link and reset your password.') . '</p>';
		    wp_logout();
		    $this->ll_login_footer();
		    exit;
		}

		$d = get_user_meta( $id, 'll_password_changed_date', true);


		// if there's no datestamp then the psw hasn't been changed since this plugin was activated.
		// so set the last change date to be today in case the admin enables password change policies
		if ('' == $d) {
		    $d = time();
		    update_user_meta( $id, 'll_password_changed_date', $d );
		}

		// number of seconds since last change
		$diff = ( time() - $d );
		// number of days since last change
		$days_since = ($diff / $day);
		// time to change password because the psw is too old?
		if ( $this->ll_options['force_psw_changes'] && 
		    $this->ll_options['psw_change_days'] &&  
		    ( $days_since > $this->ll_options['psw_change_days'] )
		    ) 
		{ 
		    $this->ll_force_reset_psw();
		    exit;
		}
	}


	function ll_force_reset_psw() { 
		global $wpdb, $current_user, $wp_locale;

		// hopefully a fix for problems with " is_rtl() is not a function " 
		if ( !$wp_locale ) { 

			require_once( ABSPATH . '/wp-includes/locale.php' );
			$wp_locale = new WP_Locale();

		}

		get_currentuserinfo();

		if (!$current_user) return;

		$user_login = $current_user->data->user_login;

		$key = $wpdb->get_var($wpdb->prepare("SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s", $user_login));

		if ( empty($key) ) {
			// Generate something random for a key...
			$key = wp_generate_password(20, false);
			do_action('retrieve_password_key', $user_login, $key);
			// Now insert the new md5 key into the db
			$wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_login' => $user_login));
		}


		$this->ll_reset_psw( $key, $user_login );
		exit;

	}


	// from WordPress Core
	function ll_login_header($title = 'Log In', $message = '', $wp_error = '') {
		global $error, $is_iphone, $interim_login, $current_site;

		if ( !function_exists( 'login_header' ) ) {

			ob_start(); 
			require_once( ABSPATH . '/wp-login.php' );
			ob_end_clean(); 

		}

		login_header( $title, $message, $wp_error );

/*
		add_filter( 'pre_option_blog_public', '__return_zero' );
		add_action( 'login_head', 'noindex' );

		if ( empty($wp_error) )
			$wp_error = new WP_Error();


		$shake_error_codes = array( 'empty_password', 'empty_email', 'invalid_email', 'invalidcombo', 'empty_username', 'invalid_username', 'incorrect_password' );
		$shake_error_codes = apply_filters( 'shake_error_codes', $shake_error_codes );

		if ( $shake_error_codes && $wp_error->get_error_code() && in_array( $wp_error->get_error_code(), $shake_error_codes ) )
			add_action( 'login_head', 'wp_shake_js', 12 );

		?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" <?php language_attributes(); ?>>
<head>
	<title><?php bloginfo('name'); ?> &rsaquo; <?php echo $title; ?></title>
	<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />
<?php
	wp_admin_css( 'login', true );
	wp_admin_css( 'colors-fresh', true );

	if ( $is_iphone ) { ?>
	<meta name="viewport" content="width=320; initial-scale=0.9; maximum-scale=1.0; user-scalable=0;" />
	<style type="text/css" media="screen">
	form { margin-left: 0px; }
	#login { margin-top: 20px; }
	</style>
<?php
	} elseif ( isset($interim_login) && $interim_login ) { ?>
	<style type="text/css" media="all">
	.login #login { margin: 20px auto; }
	</style>
<?php
	}

	do_action( 'login_enqueue_scripts' );
	do_action( 'login_head' ); ?>
</head>
	<body class="login">
	<?php   if ( !is_multisite() ) { ?>
	<div id="login"><h1><a href="<?php echo apply_filters('login_headerurl', 'http://wordpress.org/'); ?>" title="<?php echo apply_filters('login_head
	ertitle', esc_attr__('Powered by WordPress')); ?>"><?php bloginfo('name'); ?></a></h1>
	<?php   } else { ?>
	<div id="login"><h1><a href="<?php echo apply_filters('login_headerurl', network_home_url() ); ?>" title="<?php echo apply_filters('login_headertitle', esc_attr($current_site->site_name) ); ?>"><span class="hide"><?php bloginfo('name'); ?></span></a></h1>
	<?php   }

		$message = apply_filters('login_message', $message);
		if ( !empty( $message ) ) echo $message . "\n";

		// Incase a plugin uses $error rather than the $errors object
		if ( !empty( $error ) ) {
			$wp_error->add('error', $error);
			unset($error);
		}

		if ( $wp_error->get_error_code() ) {
			$errors = '';
			$messages = '';
			foreach ( $wp_error->get_error_codes() as $code ) {
				$severity = $wp_error->get_error_data($code);
				foreach ( $wp_error->get_error_messages($code) as $error ) {
					if ( 'message' == $severity )
						$messages .= '  ' . $error . "<br />\n";
					else
						$errors .= '    ' . $error . "<br />\n";
				}
			}
			if ( !empty($errors) )
				echo '<div id="login_error">' . apply_filters('login_errors', $errors) . "</div>\n";
			if ( !empty($messages) )
				echo '<p class="message">' . apply_filters('login_messages', $messages) . "</p>\n";
		}
	*/

	}


	// front WordPress Core
	function ll_login_footer($input_id = '') {

		if ( !function_exists( 'login_header' ) ) {

			ob_start(); 
			require_once( ABSPATH . '/wp-login.php' );
			ob_end_clean(); 

		}

		login_footer( $input_id );

	/******

		echo "</div>\n";

		if ( !empty($input_id) ) {
	    ?>
	    <script type="text/javascript">
	    try{document.getElementById('<?php echo $input_id; ?>').focus();}catch(e){}
	    if(typeof wpOnload=='function')wpOnload();
	    </script>
	    <?php
		    }
	    ?>
	    <p id="backtoblog"><a href="<?php bloginfo('wpurl'); ?>/" title="<?php esc_attr_e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
	    <?php do_action('login_footer'); ?>
	    </body>
	    </html>
	    <?php

	********/

	}


	function login_notice_check() { 
		global $user_ID;
		if (!$user_ID) return;
		if (!function_exists('wp_remote_get')) return;
		$lt = get_user_meta($user_ID, 'login_last_check', true);
		if ( '' != $lt || ( time() - $lt ) < 3600 ) return;
		update_user_meta($user_ID, 'login_last_check', time() );
		$args = array('sslverify' => false /*, 'blocking' => false */ );
		$url = 'http://rocketpress.me/api/public/notice.php';
		$notice = wp_remote_get( $url, $args ); 
		if ( '200' == $notice['response']['code'] && '' != $notice['body'] ) { 
			$notice = explode(';;', $notice['body']);
			if ( is_array( $notice ) && ( count($notice) > 0 ) && '' != $notice[1] ) { 
				$n = get_user_meta($user_ID, 'login_notice_msg', true);
				if ( '' == $n || (is_array($n) && ($n[0] != $notice[0]) ) ) {
					    update_user_meta( $user_ID, 'login_notice_show', true );
				}
				update_user_meta($user_ID, 'login_notice_msg', $notice );
			}
		}
	}


	function login_notice_show() {
		global $user_ID;
		if ( get_user_meta( $user_ID, 'login_notice_show', true ) == false ) return;
		$msg = get_user_meta( $user_ID, 'login_notice_msg', true );
		if ( !is_array($msg) ) return;
		if ( count($msg) < 3 ) return;
		echo '<div id="loginlock_notice" class="'.$msg[1].'"><p>';
		_e($msg[2]);
		echo ' &nbsp; (';
		printf( '<a href="%s" id="loginlock_notice">' . __('Do not remind me again') . '</a>', '?login_notice_show=0' );
		echo ')</p></div>';
	}

	
	function llajax_submit() {
	    $uid = $_POST['uid'];
	    if ( intval($uid) <= 0 ) exit;
	    $n = $_POST['n'];
	    if ( ! wp_verify_nonce( $n, 'llajax-nonce' ) ) exit;
	    update_user_meta($uid, 'login_notice_show', '');
	    exit;
	}


	// from WordPress Core
	function ll_check_password_reset_key($key, $login) {
		global $wpdb;

		$key = preg_replace('/[^a-z0-9]/i', '', $key);

		if ( empty( $key ) || !is_string( $key ) )
			return new WP_Error('invalid_key', __('Invalid key'));
	
		if ( empty($login) || !is_string($login) )
			return new WP_Error('invalid_key', __('Invalid key'));

		$user = $wpdb->get_row($wpdb->prepare("SELECT * FROM $wpdb->users WHERE user_activation_key = %s AND user_login = %s", $key, $login));

		if ( empty( $user ) )
			return new WP_Error('invalid_key', __('Invalid key'));

		return $user;
	}


	// from WordPress Core - but modified a little bit
	function ll_reset_psw( $key, $login ) { 

		$user = $this->ll_check_password_reset_key( $key, $login );

		if ( is_wp_error($user) ) {
			$this->ll_login_header(__('Reset Password'), '<p class="message reset-pass">' . __('Your password reset key is invalid.') . '</p>', $errors );
			// ( site_url('wp-login.php?action=lostpassword&error=invalidkey') );
			exit;
		}

		$errors = '';

		if ( isset($_POST['ll_reset_password']) && !wp_verify_nonce($_POST['ll_reset_password'], 'll_reset_psw') ) { 

			$errors = new WP_Error('password_reset_auth_error', __('You are not authorized to take that action!'));

		} else if ( isset($_POST['pass1']) && $_POST['pass1'] != $_POST['pass2'] ) {

			$errors = new WP_Error('password_reset_mismatch', __('The passwords do not match.'));

		} else if ( ( isset( $_POST['pass1'] ) && !empty( $_POST['pass1'] ) ) && ( true !== $this->ll_test_new_psw( $_POST['pass1'], $login ) ) ) { 

			$errors = new WP_Error('password_reset_mismatch', __('You cannot reuse that password yet. Please choose a different password.'));

		} else if ( isset( $_POST['pass1'] ) && !empty( $_POST['pass1'] ) && $msg = $this->ll_check_psw_strength( $_POST['pass1'] ) ) { 

			    $errors = new WP_Error('password_policy_error', __($msg));

		} elseif ( isset($_POST['pass1']) && !empty($_POST['pass1']) ) {

			    do_action('password_reset', $user, $_POST['pass1']);
			    wp_set_password($_POST['pass1'], $user->ID);
			    wp_password_change_notification($user);
			    delete_user_meta($user->ID, 'll_force_password_change_now');
			    $this->ll_login_header(__('Password Reset'), '<p class="message reset-pass">' . __('Your password has been reset.') . ' <a href="' . site_url('wp-login.php', 'login') . '">' . __('Log in') . '</a></p>');
			    $this->ll_login_footer();
			    exit;

		}

		if (isset($errors->errors['password_reset_auth_error'])) {
		    $msg = 'You are not authorized to take that action';
		    $this->ll_login_header('', '', $errors); 
		    exit;
		}

		wp_enqueue_script('utils');
		wp_enqueue_script('user-profile');

		$msg = __('You must reset your password.').'<br/><br/>';

		if ('yes' == $this->ll_options['psw_reuse'])

		$msg .= __('You may not reuse old passwords!').'<br/><br/>';

		$msg .= __('Enter your new password below:');

		$this->ll_login_header(__('Reset Password'), '<p class="message reset-pass ">' . $msg . '</p>', $errors );


	?>
	    <form name="resetpassform" id="resetpassform" action="<?php echo site_url('wp-login.php?action=resetpass&key=' . urlencode($key) . '&login=' . urlencode($login) , 'login_post') ?>" method="post">
		<input type="hidden" id="user_login" value="<?php echo esc_attr( $_GET['login'] ); ?>" autocomplete="off" />
		<?php wp_nonce_field('ll_reset_psw', 'll_reset_password'); ?>
		<p>
			<label><?php _e('New password') ?><br />
			<input type="password" name="pass1" id="pass1" class="input" size="20" value="" autocomplete="off" /></label>
		</p>
		<p>
			<label><?php _e('Confirm new password') ?><br />
			<input type="password" name="pass2" id="pass2" class="input" size="20" value="" autocomplete="off" /></label>
		</p>

		<div id="pass-strength-result" class="hide-if-no-js"><?php _e('Strength indicator'); ?></div>
		<p class="description indicator-hint">
		    <strong>
		    <span style="color:#cf0000">
			<?php _e('NOTE');?>: 
		    </span>
		    <?php _e('The password must be at least');
			echo ' '.$this->ll_options['psw_length'].' ';
		    ?>

		    <?php _e('characters long.');?>

		    <?php 
			if ('high' == $this->ll_options['psw_policy'] ) { 
			    _e('You must include upper and lower case letters, numbers, and symbols like ! " ? $ % ^ &amp; ).');
			} else if  ('medium' == $this->ll_options['psw_policy'] ) { 
			    _e('You must include upper and lower case letters and numbers.');
			}
		    ?>
		    </strong>
		</p>

		<br class="clear" />
		<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button-primary" value="<?php esc_attr_e('Reset Password'); ?>" tabindex="100" /></p>
	    </form>

	<p id="nav">
	<a href="<?php echo site_url('wp-login.php', 'login') ?>"><?php _e('Log in') ?></a>
	<?php if (get_option('users_can_register')) : ?>
	| <a href="<?php echo site_url('wp-login.php?action=register', 'login') ?>"><?php _e('Register') ?></a>
	<?php endif; ?>
	</p>

	<?php
	$this->ll_login_footer('user_pass');
	exit;
	}


	function ll_check_psw_strength_hook( $user, $pass1='', $pass2='' ) { 
		global $ll_psw_check_failed;

		if ('' == $pass1) $pass1 = $_POST['pass1'];
		if ('' == $pass2) $pass2 = $_POST['pass2'];

		if ('' == $pass1 && '' == $pass2) return;

		if ( !isset( $pass1 ) || !isset( $pass2 ) ) 
		    return;

		$msg = '';

		$ll_psw_check_failed = '';


		$msg = $this->ll_check_psw_strength( $pass1 );

		if ('' != $msg ) 
		    $ll_psw_check_failed = $msg;

		$msg = $this->ll_test_new_psw( $pass1, $user ); // can't reuse psws?

		if ( '' != $msg && $msg !=1 ) 
		    $ll_psw_check_failed = $msg;

	}


	// used to pass info back to the profile editor in case of errors
	function ll_psw_error_hook( $errors, $update, $user ) { 
		global $ll_psw_check_failed;

		if ( '' != $ll_psw_check_failed ) { 
		    $errors->add( 'pass', __( '<strong>ERROR:</strong> ' . $ll_psw_check_failed ) );
		}

		if ( count( $errors->errors ) <= 0 && !empty( $user->ID ) ) { 
		    $this->save_psw_hash( $user );
		    delete_user_meta( $user->ID, 'll_force_password_change_now');
		}

	} 


	function ll_show_policy_notices() { 

		if ( 'yes' != $this->ll_options['force_psw_changes'] ) 
		    return;

		?>
		<table class="form-table">
		<tbody>
		<tr id="password">
		    <th><label for="pass1">Password Policies</label></th>
		    <td>
			<strong>
			<?php
			if ('high' == $this->ll_options['psw_policy'] ) 
			    _e('You MUST include upper and lower case letters, numbers, and symbols like ! " ? $ % ^ &amp; ).');
			else if  ('medium' == $this->ll_options['psw_policy'] )
			    _e('You MUST include upper and lower case letters and numbers.');

			?>
			</strong>
		    </td>
		<tr>
		</tbody>
		</table>
		<?php
	}


	function ll_check_psw_strength( $pass ) { 

		// policies enabled?
		if ( 'yes' != $this->ll_options['force_psw_changes'] ) 
		    return;

		$pass = trim($pass);

		$nums = '1234567890';

		$specials = array('!', '@', '$', '%', '^', '&', '*', '(', ')', '_', '-', 
				    '=', '+', '`', '~', '[', ']', '{', '}', ';', ':', '"', "'",
				    ',', '.', '<', '>', '/', '?', '\\', '|'   );

		$upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$lower = 'abcdefghijklmnopqrstuvwxyz';

		// load list of common passwords - we don't allow these! 
		$bad_pass = '';
		require_once( dirname(__FILE__) . '/loginlock_psws.php'); 
		$bad_pass = explode( "\n", $bad_pass );

		$ps = strtolower($pass); 

		if ( in_array($ps, $bad_pass) === true ) { 
			$msg = __('Your password is one of the most commonly used passwords! Pick a different one.');
			return $msg;
		}

		$got_nums = false;
		$got_specials = false;
		$got_upper = false;
		$got_lower = false;
		$msg = '';

		if ('high' == $this->ll_options['psw_policy'] ) { 

		    for ($i = 0; $i <= strlen($pass); $i++) { 
			if ( strpos( $nums, substr( $pass, $i, 1) ) !== false )
			    $got_nums = true;
			if ( in_array( substr( $pass, $i, 1), $specials ) )
			    $got_specials = true;
			if ( strpos( $upper, substr( $pass, $i, 1) ) !== false )
			    $got_upper = true;
			if ( strpos( $lower, substr( $pass, $i, 1) ) !== false )
			    $got_lower = true;
		    }

		    if ( !$got_nums || !$got_specials || !$got_lower || !$got_upper)
			$msg = __('You MUST include upper and lower case letters, numbers, and symbols like ! " ? $ % ^ &amp; ).');

		} else if  ('medium' == $this->ll_options['psw_policy'] ) { 

		    for ($i = 0; $i <= strlen($pass); $i++) { 
			if ( strpos( $nums, substr( $pass, $i, 1) ) !== false )
			    $got_nums = true;
			if ( strpos( $upper, substr( $pass, $i, 1)) !== false )
			    $got_upper = true;
			if ( strpos( $lower, substr( $pass, $i, 1) ) !== false )
			    $got_lower = true;
		    }

		    if ( !$got_nums || !$got_lower || !$got_upper)
			$msg = __('You MUST include upper and lower case letters and numbers.');

		}

		if ( strlen($pass) < $this->ll_options['psw_length'] )
		    $msg .= '<br/>' . __('Your password is too short');

		return $msg;
	}


	function ll_check_active_time() {
		global $user_ID; 

		if( !$user_ID ) return;

		if (!$this->ll_options) return;

		$it = intval($this->ll_options['idle_timer']);

		if ($it <= 0) return;

		$last_active = $this->ll_get_last_active_time();

		$idle_timer = $this->ll_options['idle_timer'] * 60;

		if( ($idle_timer + $last_active) < time() ) {

			wp_logout();
			wp_redirect( wp_login_url() );

		} else {

			$this->ll_update_last_active();

		}

	}


	function ll_update_login_timestamp( $username = '' ) {
		$u = get_user_by( 'login', $username );
		$uid = $u->ID;
		if ( intval($uid) <= 0) return;
		update_user_meta( $uid, 'll_last_active', time() );
	}


	function ll_get_last_active_time() {
		global $user_ID; 
		if ( !$user_ID ) return 0;
		$la = get_user_meta( $user_ID, 'll_last_active', true );
		return $la;
	}


	function ll_update_last_active() {
		global $user_ID; 
		if ( !$user_ID ) return;
		update_user_meta( $user_ID, 'll_last_active', time() );
	}


	function llp_validate( $input ) {

		$input['max_login_retries'] = intval( $input['max_login_retries']);
		if ($input['max_login_retries'] < 1) $input['max_login_retries'] = 1;

		$input['retries_within'] = intval( $input['retries_within']);
		if ($input['retries_within'] < 1) $input['retries_within'] = 1;

		$input['lockout_length'] = intval( $input['lockout_length']);
		if ($input['lockout_length'] < 1) $input['lockout_length'] = 1;

		$input['max_login_retries'] = intval( $input['max_login_retries']);
		if ($input['max_login_retries'] < 1) $input['max_login_retries'] = 1;

		$input['force_psw_changes'] = ( $input['force_psw_changes'] == 'yes' ? 'yes' : 'no' );

		$input['psw_change_days'] = intval( $input['psw_change_days']);
		if ($input['psw_change_days'] < 0) $input['psw_change_days'] = 0;

		$input['idle_timer'] = intval( $input['idle_timer']);
		if ($input['idle_timer'] < 0) $input['idle_timer'] = 0;

		$input['psw_length'] = intval( $input['psw_length']);
		if ($input['psw_length'] > 64) 	$input['psw_length'] = 64;
		if ($input['psw_length'] < 4) 	$input['psw_length'] = 4;

		if ( '' == trim($input['psw_policy'])) 
			$input['psw_policy'] == 'high';

		$input['psw_reuse'] = ( $input['psw_reuse'] == 'yes' ? 'yes' : 'no' );

		return $input;
	}


	function admin_settings() {
		global $wpdb, $csa;

		if ( !current_user_can('activate_plugins') ) { 
		?>
		    <div class=wrap>
			<p>You do not have permission to access this page.</p>
		    </div>
		<?php
		    return;
		}

		// Emergency password reset activated? 
		if ( !empty($_POST) && !isset($_POST['emergency_psw_change']) && $_POST['emergency'] ) {
		    ?>
		    <div class="error settings-error" id="setting-error-settings_updated"> 
			<p style="padding: 7px; background-color: #cf0000; color:#fff; font-weight:bold; font-style:italic">
			    YOU DID NOT CHECK THE BOX!
			</p>
		    </div>
		    <?php 
		} else if ( !empty($_POST) && 'go' == $_POST['emergency_psw_change'] && wp_verify_nonce( $_POST['reset_all_psws_now'], 'emergency_psw_reset') ) { 
			// set the flag for each user account
			$msgs = $this->force_user_password_change_now();
			?>
			<div class="error settings-error" id="setting-error-settings_updated"> 
			    <p style="padding: 7px; background-color: #cf0000; color:#fff; font-weight:bold; font-style:italic">
				DONE. ALL USER PASSWORDS HAVE BEEN RESET TO A RANDOM VALUE.
			    </p>
			<?php 
				if ( count($msgs) > 0 ) { 
					for ($i=0; $i < count($msgs); $i++) { 
						echo '<p>'.$msgs[$i].'</p>';
					}
				}
			?>
			</div>
			<?php
		}


		if (isset($_POST['release_lockdowns'])) {

			check_admin_referer('release-lockouts');

			if ( isset( $_POST['releaselocks'] ) && !empty( $_POST['releaselocks'] ) ) {

				$released = $_POST['releaselocks'];

				foreach ( $released as $release_id ) {
					$sql = "update " . $this->lock_table . " set release_date = now() where lockdown_ID = '%s' ";
					$sql = $wpdb->prepare( $sql, $release_id);
					$results = $wpdb->query( $sql );
				}
			}
			?>
			<div class="updated"><p><strong><?php _e("Locked out IPs released.", "loginlockdown");?></strong></p></div>
			<?php
		}

		$locklist = $this->list_locks();

		$usercount = $wpdb->get_var('select count(*) from '.$wpdb->users);

	?>

	<script>
	jQuery(document).ready(function(){	
		jQuery("a").easyTooltip();
	});
	</script>

	<div class=wrap>

	    <div class="icon32" id="icon-options-general"><br></div>


	    <h2>
		<?php _e('Login Lock', 'loginlockdown') ?>
		<?php /*
		<div style="padding-left:40px;">
		<?php  // <a href="http://www.facebook.com/" target="_blank"><img src="<?php echo plugins_url( 'images/facebook.png', __FILE__ ); ?>" alt="" /></a> ?>
		<a href="http://twitter.com/wpsecurity" target="_blank"><img src="<?php echo plugins_url( 'images/twitter.png', __FILE__ ); ?>" alt="" /></a>
		<a href="https://wpsecurity.net/feed" target="_blank"><img src="<?php echo plugins_url( 'images/rss2.png', __FILE__ ); ?>" alt="" /></a>
		</div>
		*/ ?>
		<p style="margin-left: 40px"><iframe src="http://www.facebook.com/plugins/like.php?href=https%3A%2F%2Fwpsecurity.net&amp;layout=standard&amp;show_faces=false&amp;width=550&amp;action=recommend&amp;font=lucida+grande&amp;colorscheme=light&amp;height=35" scrolling="no" frameborder="0" style="border:none; overflow:hidden; width:550px; height:35px;" allowTransparency="true"></iframe></p>
	    </h2>


	    <div style="width:65%;" class="postbox-container">
	    <div class="metabox-holder">	
	    <div class="meta-box-sortables ui-sortable">

	    <form method="post" action="options.php" class="postbox">

		<?php settings_fields('llp_options'); ?>
		<?php $this->ll_options = get_option('llp_options'); ?>

		<div>
			<h3>Login Protection Settings</h3>


			<div style="background-color: #FFFBCC; padding: 10px;">
				<?php _e('If someone attempts ', 'loginlockdown') ?>
				<input class="tip" title="testing" type="text" name="llp_options[max_login_retries]" size="4" value="<?php echo esc_attr($this->ll_options["max_login_retries"]); ?>">
				<?php _e('logins that have invalid usernames or passwords within ', 'loginlockdown') ?>

				<input type="text" name="llp_options[retries_within]" size="4" value="<?php echo esc_attr($this->ll_options["retries_within"]); ?>">
				<?php _e('minutes', 'loginlockdown') ?>
				<br/>
				<?php _e('then block their IP address for ', 'loginlockdown') ?>
				<input type="text" name="llp_options[lockout_length]" size="4" value="<?php echo esc_attr($this->ll_options["lockout_length"]); ?>"> 
				<?php _e('minutes ', 'loginlockdown') ?>
				<a title=" Suggested settings: 5 attempts in 30 minutes, block for 60 minutes " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
			</div>



			<table class="form-table">
			<tbody>

			    <tr valign="top">
				<th scope="row"><label for="blogdescription"><?php _e('Email all admins?', 'loginlockdown') ?></label>
				    <a title=" It's probably a good idea to leave this enabled so that you're aware when people might be trying to break into your site " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
				</th>
				<td>
				    <input type="radio" name="llp_options[notify_admins]" value="yes" <?php if( $this->ll_options["notify_admins"] == "yes" ) echo "checked"; ?>>&nbsp;Yes&nbsp;&nbsp;&nbsp;
				    <input type="radio" name="llp_options[notify_admins]" value="no" <?php if( $this->ll_options["notify_admins"] == "no" ) echo "checked"; ?>>&nbsp;No
				    </br>
				    <span class="description"> &nbsp; (When enabled all administrators will receive a notice each time an IP address is blocked)</span>
				</td>
			    </tr>

			</tbody>
			</table>
		</div>



		<div>
			<h4 style="margin-left: 10px">Password Policy Settings</h4>

			<table class="form-table">
			<tbody>

			    <tr valign="top">
				<th scope="row"><label for="blogname"><?php _e('Enable the password policies shown below?', 'loginlockdown') ?></label>
				    <a title=" Suggested setting: Yes, enable password policies that enforce strong password selection " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
				</th>
				<td>
				    <input type="radio" name="llp_options[force_psw_changes]" value="yes" <?php if( $this->ll_options["force_psw_changes"] == "yes" ) echo "checked"; ?>>&nbsp;Yes&nbsp;&nbsp;&nbsp;
				    <input type="radio" name="llp_options[force_psw_changes]" value="no" <?php if( $this->ll_options["force_psw_changes"] == "no" ) echo "checked"; ?>>&nbsp;No
				    <br/>
				    <em><?php _e('(If disabled no password policies will be enforced)', 'loginlockdown') ?></em>
				</td>
			    </tr>

			    <tr valign="top">
				<th scope="row"><label for="blogname"><?php _e('Require password changes: ', 'loginlockdown') ?></label>
				    <a title=" Suggested setting: 30 days at most, frequent password changes make your passwords a moving target " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
				</th>
				<td>
				    Every <input type="text" name="llp_options[psw_change_days]" size="4" value="<?php echo esc_attr($this->ll_options["psw_change_days"]); ?>">
				    <?php _e('days ', 'loginlockdown') ?>
				    <br/>
				    <em><?php _e('(This forces users to change their passwords upon login every X number of days)', 'loginlockdown') ?></em>
				    <br/>
				    <em><?php _e('Set to 0 (zero) to disable this policy', 'loginlockdown') ?></em>
				</td>
			    </tr>

			    <tr valign="top">
				<th scope="row"><label for="blogname"><?php _e('Minimum password length: ', 'loginlockdown') ?> </label>
				    <a title=" Suggested setting: 12 or more characters, the longer the password the harder it is to crack " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
				</th>
				<td>
				    <input type="text" name="llp_options[psw_length]" size="4" value="<?php echo esc_attr($this->ll_options["psw_length"]); ?>">
				    <?php _e('characters', 'loginlockdown') ?>
				    <br/>
				    <em><?php _e('(Cannot be less than 4, cannot be more than 64 - the maximum length allowed by WordPress is 64)', 'loginlockdown') ?></em>
				</td>
			    </tr>

			    <tr valign="top">
				<th scope="row"><label for="blogname"><?php _e('Password strength: ', 'loginlockdown') ?></label> 
				    <a title=" Suggested setting: High, because complex passwords are more difficult to crack " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
				</th>
				<td>
				    <input type="radio" name="llp_options[psw_policy]" value="low" <?php if( $this->ll_options["psw_policy"] == "low" ) echo "checked"; ?>>
				    <?php _e('Low - no specific character requirements', 'loginlockdown') ?><br/>

				    <input type="radio" name="llp_options[psw_policy]" value="medium" <?php if( $this->ll_options["psw_policy"] == "medium" ) echo "checked"; ?>>
				    <?php _e('Medium - Require uppercase and lowercase letters, plus numbers', 'loginlockdown') ?><br/>

				    <input type="radio" name="llp_options[psw_policy]" value="high" <?php if( $this->ll_options["psw_policy"] == "high" ) echo "checked"; ?>>
				    <?php _e('High - Same as Medium, but also require special characters such as !@#$%^&*() etc.', 'loginlockdown') ?><br/>
				</td>
			    </tr>

			    <tr valign="top">
				<th scope="row"><label for="blogname"><?php _e('Password recycling:', 'loginlockdown') ?></label>
				    <a title=" Suggested setting: Yes, disallow password reuse. " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
				</th>
				<td>		
				    <?php _e('Disallow password reuse?', 'loginlockdown') ?><br/>
				    <input type="radio" name="llp_options[psw_reuse]" value="yes" <?php if( $this->ll_options["psw_reuse"] == "yes" ) echo "checked"; ?>>&nbsp;Yes&nbsp;&nbsp;&nbsp;
				    <input type="radio" name="llp_options[psw_reuse]" value="no" <?php if( $this->ll_options["psw_reuse"] == "no" ) echo "checked"; ?>>&nbsp;No
				    <br/>
				    <em><?php _e('(If enabled the last 5 passwords per user will be remembered and not allowed to be reused)', 'loginlockdown') ?></em>
				</td>
			    </tr>

			</tbody>
			</table>

		</div>


		<div>
			<h4 style="margin-left: 10px">Idle Logout</h4>

			<table class="form-table">
			<tbody>

			    <tr valign="top">
				<th scope="row"><label for="blogname"><?php _e('Logout idle users', 'loginlockdown') ?></label>
				    <a title=" Suggested setting: 15 minutes at most, the helps guard against having unauthorized people use someone's logged-in account in cases where computers are shared, lost, or stolen " class="helpico"> &nbsp;  &nbsp;  &nbsp;  &nbsp; </a>
				</th>
				<td>
				    <?php _e('Logout users after'); ?> 
				    <input type="text" size="4" name="llp_options[idle_timer]" value="<?php echo $this->ll_options["idle_timer"] ?>">
				    <?php echo ' ' . __('minutes of no activity'); ?>
				    <br/>
				    <em><?php _e('Set to 0 (zero) to disable this feature.', 'loginlockdown') ?></em>
				</td>
			    </tr>

			</tbody>
			</table>
		</div>

		<div class="submit" style="margin-left: 15px">
			<input type="submit" name="update_loginlock" value="<?php _e('Update Settings', 'loginlockdown') ?>" />
		</div>

	    </form>


		<div class="postbox">
			<h3 style="color:#cf0000">Force Password Changes Now</h3>
			<form action="" method="post">
			<table class="form-table">
			<tbody>

			    <tr valign="top">
				<th scope="row"><label for="blogname"  style="color:#cf0000; font-weight:bold"><?php _e('In case of emergency', 'loginlockdown') ?></label></th>
				<td>
				    <?php wp_nonce_field('emergency_psw_reset', 'reset_all_psws_now'); ?>
				    <input type="hidden" name="emergency" value="1">
				    <input type="checkbox" name="emergency_psw_change" value="go"> 
					<span  style="color:#cf0000; font-weight:bold">
					    <?php _e('Logout all users and force password changes now', 'lockdown');?>
					</span>
				    </br>
				    <span class="description"> &nbsp; (Check the box and click the button below to force all users - INCLUDING YOU - to change their passwords the next time they access this site)</span>
				    <br/><br/>
				    <span class="description">NOTE: When you do this ALL user passwords will be reset to a random value, ALL users will receive an email message instructing them to reset their passwords, and ALL users will be forcibly logged out immediately - INCLUDING YOU!</span>
				    <br/><br/>
				    <span class="description">You currently have <?php echo $usercount ?> users in your database. If you have more than 100 users then using this feature might cause your hosting company or mail service provider to flag your account for sending too many email messages too fast!</span>
				</td>
			    </tr>

			</tbody>
			</table>
			<div class="submit">
				<input style="color:#cf0000;font-weight:bold; margin-left: 15px" type="submit" name="panic_button" value="<?php _e('Force Password Changes Now', 'loginlockdown') ?>" />
			</div>
			</form>
		</div>



		<div class="postbox">
			<h3><?php _e('Blocked IP Addresses', 'loginlockdown') ?></h3>

			<form method="post" action="<?php echo esc_attr($_SERVER["REQUEST_URI"]); ?>">
			    <?php
			    if ( function_exists('wp_nonce_field') )
				    wp_nonce_field('release-lockouts');
			    ?>
			    <?php
				    $num_lockedout = count($locklist);

				    if( 0 == $num_lockedout ) {

					    _e('<p style="margin-left: 15px">No IP addresses are blocked.</p>', 'lockdown');

				    } else {

					    echo '<ul style="margin-left: 15px">';

					    foreach ( $locklist as $key => $val ) {
						    ?>
						    <li>
							<input type="checkbox" name="releaselocks[]" value="<?php echo $val['lockdown_ID']; ?>"> 
							<?php echo $val['lockdown_IP']; ?> 
							(<?php echo $val['minutes_left']; ?> 
							<?php echo ' '. __('minutes remaining', 'wpsec') . ')'; ?>
						    </li>
						    <?php
					    }

					    echo '</ul>';

				    }
			    ?>
			    <?php if ( count($locklist) > 0) { ?>
			    <div class="submit">
				<input style="margin-left: 15px" type="submit" name="release_lockdowns" value="<?php _e('Unblock Selected', 'loginlockdown') ?>" />
			    </div>
			    <?php } ?>

			</form>
		</div>


	    </div>
	    </div>
	    </div>

	    <div style="width:20%; margin-left: 5px" class="postbox-container">
		    <div class="metabox-holder">	
			    <div class="meta-box-sortables ui-sortable">
				<?php $csa->plugin_like(); ?>
				<?php
				$csa->postbox('donate','<strong class="red">Donate $10, $20 or $50!</strong>',
				'<p>This plugin represents countless hours of work, if you use it please donate a token of your appreciation!</p><br/>
				<form style="margin-left: 40px" action="https://www.paypal.com/cgi-bin/webscr" method="post">
				<input type="hidden" name="cmd" value="_s-xclick">
				<input type="hidden" name="hosted_button_id" value="8D8XCLF9BPJRY">
				<input type="image" src="https://www.paypalobjects.com/WEBSCR-640-20110401-1/en_US/i/btn/btn_donateCC_LG.gif" border="0" name="submit" alt="PayPal - The safer, easier way to pay online!">
				<img alt="" border="0" src="https://www.paypalobjects.com/WEBSCR-640-20110401-1/en_US/i/scr/pixel.gif" width="1" height="1">
				</form>
				');
				?>
				<?php $csa->plugin_support(); ?>
				<?php $csa->plugin_sponsors(); ?>
				<?php $csa->news(); ?>
			    </div>
		    </div>
	    </div>


	</div>

	<?php
	}


	function add_page() {
		if ( function_exists('add_options_page') && current_user_can('activate_plugins') ) { // just in case, wth.
			add_options_page('Login Lock', 'Login Lock', 'activate_plugins', basename(__FILE__), array( &$this, 'admin_settings') );
		}
	}


	function login_lock_notice(){
		echo '<p style="margin-bottom: 20px">Site protected by <a href="https://wpsecurity.net">LOGIN LOCK</a><br/>Strong <a href="https://wpsecurity.net">WordPress Security</a></p>';
	}


	function ll_styles() { 
		if ( !is_admin() ) return;
		global $user_ID;
		$color = get_user_meta( get_current_user_id(), 'admin_color', true );
		wp_enqueue_style(  'metabox-tabs', WPSEC_LOGINLOCK_URL.'css/metabox-tabs.css', '', WPSEC_LOGINLOCK_VERSION );
		wp_enqueue_style(  "metabox-$color", WPSEC_LOGINLOCK_URL.'css/metabox-'.$color.'.css', '', WPSEC_LOGINLOCK_VERSION );
		wp_enqueue_style(  "wpsec-login", WPSEC_LOGINLOCK_URL.'css/wpsec-login.css', '', WPSEC_LOGINLOCK_VERSION );
		wp_register_script( 'easytooltip', WPSEC_LOGINLOCK_URL.'js/easytooltip/js/easyTooltip.js', 'jquery', WPSEC_LOGINLOCK_VERSION, false );
		wp_enqueue_script( 'easytooltip' );
		wp_register_script( 'loginlock', WPSEC_LOGINLOCK_URL.'js/loginlock.js', 'jquery, common', WPSEC_LOGINLOCK_VERSION, false );
		wp_enqueue_script( 'loginlock' );
		wp_localize_script( 'loginlock', 'llajax', array( 'ajaxurl' => admin_url('admin-ajax.php'), 'uid' => $user_ID, 'n' => wp_create_nonce( 'llajax-nonce' ) ) );
	}


	// Michael VanDeMar
	function ll_wp_authenticate($user, $username, $password) {

		if ( is_a( $user, 'WP_User' ) ) { 
			return $user; 
		}

		if ( empty($username) || empty($password) ) {

			$error = new WP_Error();

			if ( empty($username) )
				$error->add('empty_username', __('<strong>ERROR</strong>: You must enter a username.'));

			if ( empty($password) )
				$error->add('empty_password', __('<strong>ERROR</strong>: You must enter a password'));

			return $error;
		}

		$userdata = get_user_by( 'login', $username );

		if ( !$userdata ) {
			return new WP_Error('invalid_username', sprintf(__('<strong>ERROR</strong>: Invalid username. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), site_url('wp-login.php?action=lostpassword', 'login')));
		}

		$userdata = apply_filters('wp_authenticate_user', $userdata, $password);
		if ( is_wp_error($userdata) ) {
			return $userdata;
		}

		if ( !wp_check_password($password, $userdata->user_pass, $userdata->ID) ) {
			return new WP_Error('incorrect_password', sprintf(__('<strong>ERROR</strong>: Incorrect password. <a href="%s" title="Password Lost and Found">Lost your password</a>?'), site_url('wp-login.php?action=lostpassword', 'login')));
		}

		$user =  new WP_User($userdata->ID);
		return $user;
	}






} // end class


global $loginlock;
$loginlock = new LoginLock();


// this function is based largely on core WordPress code
if (!function_exists('wp_authenticate')) { 
	function wp_authenticate($username, $password) {
		global $wpdb, $error, $loginlock;

		$username = sanitize_user($username);
		$password = trim($password);

		if ( "" != $loginlock->is_locked_out() ) {
				return new WP_Error('incorrect_password', __("<strong>ERROR</strong>: You've been blocked due to too many failed login attempts."));
		}

		$user = apply_filters('authenticate', null, $username, $password);

		if ( $user == null ) {
			$user = new WP_Error('authentication_failed', __('<strong>ERROR</strong>: Invalid username or password.'));
		}

		$ignore_codes = array('empty_username', 'empty_password');

		if (is_wp_error($user) && !in_array($user->get_error_code(), $ignore_codes) ) {

			$loginlock->increment_failed($username);

			if ( $loginlock->ll_options['max_login_retries'] <= $loginlock->count_failed($username) ) {
				$loginlock->lockout($username);
				return new WP_Error('incorrect_password', __("<strong>ERROR</strong>: You've been blocked due to too many failed login attempts."));
			}

			return new WP_Error('authentication_failed', sprintf(__('<strong>ERROR</strong>: Invalid username or password. <a href="%s" title=" Lost your password? ">Lost your password</a>?'), site_url('wp-login.php?action=lostpassword', 'login')));

		}

		return $user;
	}
}

?>
