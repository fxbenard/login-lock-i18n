jQuery(document).ready(function() { 
	jQuery("#loginlock_notice").click(function(){
		jQuery.post( llajax.ajaxurl, {
	        	action : 'll_notice_hide',
		        uid : llajax.uid,
			n : llajax.n
			}, 
			function( response ) {}
		);
		jQuery('#loginlock_notice').hide();
		return false;
	});
});
