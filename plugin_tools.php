<?php

/**
 * Backend Class - by Yoast, Copyright (c) Joost de Valk
 * 
 */

if ( !class_exists('Custom_Plugin_Admin') ) {
	class Custom_Plugin_Admin {

		var $hook 	= 'login-lock';
		var $filename	= '';
		var $longname	= '';
		var $shortname	= '';
		var $ozhicon	= '';
		var $optionname = '';
		var $homepage	= 'https://wpsecurity.net';
		var $feed	= 'https://wpsecurity.net/feed/';
		var $accesslvl	= 'manage_options';
		
		function __construct() {
		}
		
		
		/**
		 * Create a potbox widget
		 */

		function postbox($id, $title, $content) {
		?>
			<div id="<?php echo $id; ?>" class="postbox">
				<div class="handlediv" title="Click to toggle"><br /></div>
				<h3 class="hndle"><span><?php echo $title; ?></span></h3>
				<div class="inside wpsec-inside">
					<?php echo $content; ?>
				</div>
			</div>
		<?php
		}

		/**
		 * Create a "plugin like" box.
		 */
		function plugin_like() {
			$content = '<p>'.__('Why not do any or all of the following:','wpsec').'</p>';
			$content .= '<ul>';
			$content .= '<li class="star"><a href="'.$this->homepage.'" target="_blank">'.__('Link to our site please!','wpsec').'</a></li>';
			$content .= '<li class="tweet"><a href="http://twitter.com/home?status='.urlencode('LoginLock for WordPress - http://wordpress.org/extend/plugins/login-lock/').'" target="_blank">'.__('Tweet this plugin!','wpsec').'</a></li>';
			$content .= '<li class="tweet"><a href="http://twitter.com/wpsecurity" target="_blank">'.__('Follow us on Twitter','wpsec').'</a></li>';
			$content .= '<li class="star"><a href="http://wordpress.org/extend/plugins/'.$this->hook.'/"  target="_blank">'.__('Give it a 5 star rating on WordPress.org','wpsec').'</a></li>';
			$content .= '<li class="coins"><a target="_blank" href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=8D8XCLF9BPJRY">'.__('Donate a token of your appreciation','wpsec').'</a></li>';
			$content .= '</ul>';
			$this->postbox($this->hook.'like', 'Like this plugin?', $content);
		}	
		
		/**
		 * Info box with link to the support forums.
		 */
		function plugin_support() {
			$content = '<p>'.__('If you have any problems with this plugin, or good ideas for improvements or new features, please ','wpsec').' <a href="https://wpsecurity.net/contact-us/" target="_blank">'.__("contact us!",'wpsec').'</a>.</p>';
			$this->postbox($this->hook.'support', 'Need support?', $content);
		}

		function plugin_sponsors() {
			$content = '<a target="_blank" title=" Fast Secure WordPress Hosting " href="http://rocketpress.me"><img style="margin: 7px" src="http://rocketpress.me/ads/rocketlogo-225.png"></a>';
			$this->postbox($this->hook.'support', 'Our Sponsors', $content);
		}


		function text_limit( $text, $limit, $finish = '&hellip;') {
			if( strlen( $text ) > $limit ) {
		    	$text = substr( $text, 0, $limit );
				$text = substr( $text, 0, - ( strlen( strrchr( $text,' ') ) ) );
				$text .= $finish;
			}
			return $text;
		}

		function fetch_rss_items( $num ) {
			include_once(ABSPATH . WPINC . '/feed.php');
			$rss = fetch_feed( $this->feed );
			
			// Bail if feed doesn't work
			if ( is_wp_error($rss) )
				return false;
			
			$rss_items = $rss->get_items( 0, $rss->get_item_quantity( $num ) );
			
			// If the feed was erroneously 
			if ( !$rss_items ) {
				$md5 = md5( $this->feed );
				delete_transient( 'feed_' . $md5 );
				delete_transient( 'feed_mod_' . $md5 );
				$rss = fetch_feed( $this->feed );
				$rss_items = $rss->get_items( 0, $rss->get_item_quantity( $num ) );
			}
			
			return $rss_items;
		}
		
		/**
		 * Box with latest news 
		 */
		function news() {
			$rss_items = $this->fetch_rss_items( 5 );
			
			$content = '<ul class="wpsec-rss">';
			if ( !$rss_items ) {
			    $content .= '<li class="wpsec">no news items, feed might be broken...</li>';
			} else {
			    foreach ( $rss_items as $item ) {
					$content .= '<li class="wpsec">';
					$content .= '<a target="_blank" class="rsswidget" href="'.esc_url( $item->get_permalink(), $protocolls=null, 'display' ).'">'. esc_html( $item->get_title() ) .'</a> ';
					$content .= '</li>';
			    }
			}						
			$content .= '<li class="rss"><a target="_blank" href="'.$this->feed.'">Subscribe with RSS</a></li>';
			$content .= '<li class="email"><a target="_blank" href="https://wpsecurity.net/wordpress-security-sign-up/">Subscribe by email</a></li>';
			$content .= '</ul>';
			$this->postbox('wpseclatest', 'Latest news from WPSecurity.net', $content);
		}

		/**
		 * Widget with latest news 
		 */
		function db_widget() {
			$options = get_option('wpsec_loginwidget');
			
			$network = '';
			if ( function_exists('is_network_admin') && is_network_admin() )
				$network = '_network';

			if (isset($_POST['wpsec_removedbwidget'])) {
				$options['removedbwidget'.$network] = true;
				update_option('wpsec_loginwidget',$options);
			}			
			if ( isset($options['removedbwidget'.$network]) && $options['removedbwidget'.$network] ) {
				echo "If you reload, this widget will be gone and never appear again, unless you decide to delete the database option 'wpsec_loginwidget'.";
				return;
			}

			$rss_items = $this->fetch_rss_items( 3 );
			
			echo '<div class="rss-widget">';

			echo '<div style="padding: 0px 10px; background-color: #000060; float:right"><a target="_blank" href="https://wpsecurity.net" title=" WordPress Security News - As It Occurs! "><img height="50" src="https://wpsecurity.net/wp-content/uploads/wpslogo.png" class="alignright" alt="WPSecurity.net"/></a></div>';

			echo '<ul>';

			if ( !$rss_items ) {
			    echo '<li class="wpsec">no news items, feed might be broken...</li>';
			} else {
			    foreach ( $rss_items as $item ) {
					echo '<li class="wpsec">';
					echo '<a target="_blank" class="rsswidget" href="'.esc_url( $item->get_permalink(), $protocolls=null, 'display' ).'">'. esc_html( $item->get_title() ) ;
					echo ' -- ' . $item->get_date('F j, Y') . '</a>';
					echo '<div class="rssSummary">'. esc_html( $this->text_limit( strip_tags( $item->get_description() ), 150 ) ).'</div>';
					echo '</li>';
			    }
			}						

			echo '</ul>';
			echo '<br class="clear"/><div style="margin-top:10px;border-top: 1px solid #ddd; padding-top: 10px; text-align:center;">';
			echo '<a href="'.$this->feed.'"><img src="'.get_bloginfo('wpurl').'/wp-includes/images/rss.png" alt=""/> Subscribe with RSS</a>';
			echo ' &nbsp; &nbsp; &nbsp; ';
			echo '<a target="_blank" href="https://wpsecurity.net/wordpress-security-sign-up/"><img src="'.WPSEC_LOGINLOCK_URL.'images/email_sub.png" alt=""/> Subscribe by email</a>';
			//echo '<form class="alignright" method="post"><input type="hidden" name="wpsec_removedbwidget" value="true"/><input title="Remove this widget from all users dashboards" class="button" type="submit" value="X"/></form>';
			echo '</div>';
			echo '</div>';
		}

		function widget_setup() {
			$network = '';
			if ( function_exists('is_network_admin') && is_network_admin() )
				$network = '_network';

			$options = get_option('wpsec_loginwidget');
			if ( !isset($options['removedbwidget'.$network]) || !$options['removedbwidget'.$network] )
	    		wp_add_dashboard_widget( 'wpsec_db_widget' , 'WordPress Security News' , array(&$this, 'db_widget') );
		}
		
		function widget_order( $arr ) {
			global $wp_meta_boxes;
			if ( function_exists('is_network_admin') && is_network_admin() ) {
				$plugins = $wp_meta_boxes['dashboard-network']['normal']['core']['dashboard_plugins'];
				unset($wp_meta_boxes['dashboard-network']['normal']['core']['dashboard_plugins']);
				$wp_meta_boxes['dashboard-network']['normal']['core'][] = $plugins;
			} else if ( is_admin() ) {
				if ( isset($wp_meta_boxes['dashboard']['normal']['core']['wpsec_db_widget']) ) {
					$wpsec_db_widget = $wp_meta_boxes['dashboard']['normal']['core']['wpsec_db_widget'];
					unset($wp_meta_boxes['dashboard']['normal']['core']['wpsec_db_widget']);
					if ( isset($wp_meta_boxes['dashboard']['side']['core']) ) {
						$begin = array_slice($wp_meta_boxes['dashboard']['side']['core'], 0, 1);
						$end = array_slice($wp_meta_boxes['dashboard']['side']['core'], 1, 6 );
						$wp_meta_boxes['dashboard']['side']['core'] = $begin;
						$wp_meta_boxes['dashboard']['side']['core']['dashboard_wpsec_widget'] = $wpsec_db_widget;
						$wp_meta_boxes['dashboard']['side']['core'] += $end;
					} else {
						$wp_meta_boxes['dashboard']['side']['core'] = array();
						$wp_meta_boxes['dashboard']['side']['core'][] = $wpsec_db_widget;
					}
				} 
			}
			return $arr;
		}
	}
}
?>