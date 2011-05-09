<?php
/**
* Adds a reCAPTCHA to comment forms for visitors that are not logged in
* and do not have previously approved comments.
**/
class Recaptcha extends Plugin {
	private $ready = false;
	private $options;
	
	public function configure() {
		$ui = new FormUI( 'recaptcha_configuration' );
		$ui->append( 'static', 'recaptcha_info', '<p>In order to use reCAPTCHA you need to supply a key pair. You can <a href="http://code.google.com/apis/recaptcha/" target="_blank">get one for free</a>. Please enter your public and private keys below:</p>' );
		
		$public = $ui->append( 'text', 'public_key', 'recaptcha__public_key', 'Public key:' );
		$public->add_validator( 'Recaptcha::check_keys' );
		$public->size = $public->maxlength = 40;
		
		$private = $ui->append( 'text', 'private_key', 'recaptcha__private_key', 'Private key:' );
		$private->add_validator( 'Recaptcha::check_keys' );
		$private->size = $private->maxlength = 40;
		
		$ui->append( 'submit', 'save', 'Save' );
		
		return $ui;
	}
	
	static function check_keys( $text, $control, $form ) {
		$text = trim( $text );
		return ( strlen( $text ) == 40 ) ? array() : array( 'The key you supplied does not appear to be valid. Please check that it is exactly 40 characters long and contains no spaces.' );
	}
	
	
	function action_form_comment( $form ) {
		$user = User::identify();
		
		if( $user->loggedin )
			return;
		
		$this->load_options();
		if( !$this->ready )
			return;
		
		$cookie = 'comment_' . Options::get( 'GUID' );
		if ( isset( $_COOKIE[$cookie] ) ) {
			$commenter = explode( '#', $_COOKIE[$cookie], 3 );	// name, email, url
			// make sure there are always at least 3 elements
			$commenter = array_pad( $commenter, 3, null );
		
			$comments = (int) Comments::get( array( 'count' => 'name', 'name' => $commenter[0], 'email' => $commenter[1], 'status' => Comment::STATUS_APPROVED ) );
			
			if( $comments )	// previously approved comments
				return;
		}

		// show CAPTCHA and add validation
		$html = '<script src="http://www.google.com/recaptcha/api/challenge?k=' . $this->options['public_key'] .'"></script><noscript><iframe id="recaptcha-no-js" src="http://www.google.com/recaptcha/api/noscript?k=' . $this->options['public_key'] .'" height="300" width="700" frameborder="0"></iframe><br><textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
       <input type="hidden" name="recaptcha_response_field" value="manual_challenge"></noscript>';
		$recaptcha = $form->insert( 'cf_submit', 'static', 'recaptcha',  $html );
		$recaptcha->add_validator( 'Recaptcha::validate' );
	}
	
	static function validate( $text, $control, $form ) {	// note, $text will be null
		$chall = isset( $_POST['recaptcha_challenge_field'] ) ? $_POST['recaptcha_challenge_field'] : false;
		$resp = isset( $_POST['recaptcha_response_field'] ) ? $_POST['recaptcha_response_field'] : false;
		
		if ( !$chall || !$resp ) 
			$result = array( 'false', 'incorrect-captcha-sol' );		// discard spam submissions upfront
		else
			$result = Recaptcha::recaptcha_post( array('privatekey' => $this->options['private_key'], 'remoteip' => $_SERVER['REMOTE_ADDR'], 'challenge' => $chall, 'response' => $resp) );

		// if the first part isn't true then return the second part
		return ( trim($result[0]) == 'true' ) ? array() : array( 'You did not complete the reCAPTCHA correctly (' . $result[1] . ')' );
	}
	
	static function recaptcha_post($data) {
		$req = http_build_query($data);
		$host = 'www.google.com';
		
		$headers = array(
			'POST /recaptcha/api/verify HTTP/1.0',
			'Host: ' . $host,
			'Content-Type: application/x-www-form-urlencoded;',
			'Content-Length: ' . strlen($req),
			'User-Agent: reCAPTCHA/PHP'
		);
		
		$http_request = implode("\r\n", $headers)."\r\n\r\n".$req;

		$response = '';

		$fs = @fsockopen($host, 80, $errno, $errstr, 10);
		if(!$fs) return array('false','recaptcha-not-reachable');

		fwrite($fs, $http_request);
		while ( !feof($fs) ) $response .= fgets($fs, 1160); // One TCP-IP packet
		fclose($fs);
		$parts = explode("\r\n\r\n", $response, 2);			// [0] = response header, [1] = body
		return explode("\n", $parts[1]);					// [0] 'true' or 'false', [1] = error message
	}
	
	function action_plugin_deactivation() {
		Options::delete_group( 'recaptcha' );
	}
	
	function action_admin_info() {
		$this->load_options();
		if( !$this->ready )
			echo '<div class="container">The reCAPTCHA plugin is almost ready to go. Please go the the plugin configuration section to enter your API keys.</div>';
	}
	
	private function load_options() {
		$this->options = Options::get_group( 'recaptcha' );
		$this->ready = ( empty( $this->options['public_key'] ) || empty( $this->options['private_key'] ) ) ? false : true;
	}
}
?>
