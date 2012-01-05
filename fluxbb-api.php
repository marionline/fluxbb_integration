<?php
/**
 * fluxbb 
 * 
 * @author Mario Santagiuliana <mario at marionline.it> 
 * Thak you to Hakon to share his first code:
 * http://fluxbb.org/forums/viewtopic.php?id=5114
 */
class fluxbb {
	private $_db;
	private $_config;
	private $_pun_config;

	/**
	 * __construct 
	 * Loads settings from the fluxbb config file so it they becomes avaible for this class
	 * 
	 * @access protected
	 * @return void
	 */
	function __construct($PUN_ROOT, array $cookie = NULL, array $db = NULL) {
		$config_file = $PUN_ROOT . "config.php";
		if(file_exists($config_file)) {
			if(!defined('PUN_ROOT'))
				define( 'PUN_ROOT', $PUN_ROOT);
			if(!defined('PUN') OR $cookie === NULL) {
				include( $config_file );
				$this->_config['cookie_name']   = $cookie_name;
				$this->_config['cookie_domain'] = $cookie_domain;
				$this->_config['cookie_path']   = $cookie_path;
				$this->_config['cookie_secure'] = $cookie_secure;
				$this->_config['cookie_seed']   = $cookie_seed;
			} else {
				$this->_config['cookie_name']   = $cookie_name   = $cookie[0];
				$this->_config['cookie_domain'] = $cookie_domain = $cookie[1];
				$this->_config['cookie_path']   = $cookie_path   = $cookie[2];
				$this->_config['cookie_secure'] = $cookie_secure = $cookie[3];
				$this->_config['cookie_seed']   = $cookie_seed   = $cookie[4];
				$db_type     = $db[0]; 
				$db_host     = $db[1];
				$db_name     = $db[2];
				$db_username = $db[3];
				$db_password = $db[4];
				$db_prefix   = $db[5];
				$p_connect   = $db[6];
			}
			include( PUN_ROOT . "include/dblayer/common_db.php" );
			$this->_db = $db;
		} else {
			throw new Exception( "Fluxbb root parh not correct." );
		}
	}
	
	/**
	 * forum_hmac 
	 * 
	 * @param mixed $data 
	 * @param mixed $key 
	 * @param mixed $raw_output 
	 * @static
	 * @access private
	 * @return hmac code
	 */
	static private function forum_hmac($data, $key, $raw_output = false) {
		if (function_exists('hash_hmac'))
			return hash_hmac('sha1', $data, $key, $raw_output);
	
		// If key size more than blocksize then we hash it once
		if (strlen($key) > 64)
			$key = sha1($key, true); // we have to use raw output here to match the standard
	
		// Ensure we're padded to exactly one block boundary
		$key = str_pad($key, 64, chr(0x00));
		
		$hmac_opad = str_repeat(chr(0x5C), 64);
		$hmac_ipad = str_repeat(chr(0x36), 64);
	
		// Do inner and outer padding
		for ($i = 0;$i < 64;$i++) {
			$hmac_opad[$i] = $hmac_opad[$i] ^ $key[$i];
			$hmac_ipad[$i] = $hmac_ipad[$i] ^ $key[$i];
		}
	
		// Finally, calculate the HMAC
		return sha1($hmac_opad.sha1($hmac_ipad.$data, true), $raw_output);
	}

	/**
	 * getUserId 
	 * Returns the user ID for the given username
	 * 
	 * @param mixed $user 
	 * @access public
	 * @return int
	 */
	public function getUserId($user) {
		$result = $this->_db->query("SELECT * FROM ". $this->_db->prefix."users WHERE username ='" . $user . "'");
		$row = $this->_db->fetch_assoc($result);
		if(empty($row)){
			return false;
		}else{
			return $row['id'];
		}
	}

	/**
	 * hash 
	 * 
	 * @param mixed $str 
	 * @static
	 * @access public
	 * @return sha1
	 */
	static public function pun_hash($str) {
		return sha1($str);
	}
	

	/**
	 * get_pun_config 
	 * 
	 * @access protected
	 * @return array
	 */
	protected function get_pun_config(){
		global $pun_config;

		if(defined('PUN_CONFIG_LOADED')) {
			if($this->_pun_config === null)
				$this->_pun_config = $pun_config;

			return $this->_pun_config;
		}

		if(file_exists(PUN_ROOT . "/cache/cache_config.php")) {
			require(PUN_ROOT . "/cache/cache_config.php");
			$this->_pun_config = $pun_config;
		} else {
			$this->_pun_config = false;
		}
		return $pun_config;
	}

	/**
	 * authenticate_user 
	 * 
	 * @param mixed $user 
	 * @param mixed $password 
	 * @access public
	 * @return void
	 */
	public function authenticate_user($user, $password) {
		$sql = "SELECT * FROM " . $this->_db->prefix . "users WHERE username = '" . $user . "' AND password = '" . $this->pun_hash($password) . "'";
		$result = $this->_db->query($sql);
		if($this->_db->affected_rows($result) == true){
			return true;
		}else{
			return false;
		}
	}

	/**
	 * setcookie 
	 * 
	 * @param mixed $name 
	 * @param mixed $value 
	 * @param mixed $expire 
	 * @access public
	 * @return void
	 */
	public function setcookie($name, $value, $expire) {
		// Enable sending of a P3P header
		header('P3P: CP="CUR ADM"');

		if(version_compare(PHP_VERSION, '5.2.0', '>='))
			return setcookie($name, $value, $expire, $this->_config['cookie_path'], $this->_config['cookie_domain'], $this->_config['cookie_secure'], true);
		else
			return setcookie($name, $value, $expire, $this->_config['cookie_path'].'; HttpOnly', $this->_config['cookie_domain'], $this->_config['cookie_secure']);
		
	}

	/**
	 * login 
	 * Log in a user after checking username and password against the database
	 * 
	 * @param mixed $user 
	 * @param mixed $password 
	 * @access public
	 * @return void
	 */
	public function login($user, $password, $save_pass) {
		if($this->authenticate_user($user, $password)) {
			$pun_config = $this->get_pun_config();
			$expire = ($save_pass == '1') ? time() + 1209600 : time() + $pun_config['o_timeout_visit'];
			$password = $this->pun_hash($password);
			$result = $this->setcookie($this->_config['cookie_name'], $this->getUserId($user).'|'.$this->forum_hmac($password, $this->_config['cookie_seed'].'_password_hash').'|'.$expire.'|'.$this->forum_hmac($this->getUserId($user).'|'.$expire, $this->_config['cookie_seed'].'_cookie_hash'), $expire);
			// Remove this users guest entry from the online list
			if($result)
				$this->_db->query('DELETE FROM '.$this->_db->prefix.'online WHERE ident=\''.$this->_db->escape($this->get_remote_address()).'\'');
			return $result;	
		}else{
			return false;
		}
	}
	
	/**
	 * get_remote_address 
	 * 
	 * @access protected
	 * @return void
	 */
	protected function get_remote_address() {
		$remote_addr = $_SERVER['REMOTE_ADDR'];

		// If we are behind a reverse proxy try to find the real users IP
		if (defined('FORUM_BEHIND_REVERSE_PROXY'))
		{
			if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
			{
				// The general format of the field is:
				// X-Forwarded-For: client1, proxy1, proxy2
				// where the value is a comma+space separated list of IP addresses, the left-most being the farthest downstream client,
				// and each successive proxy that passed the request adding the IP address where it received the request from.
				$forwarded_for = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
				$forwarded_for = trim($forwarded_for[0]);

				if (@preg_match('%^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$%', $forwarded_for) || @preg_match('%^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|(([0-9A-Fa-f]{1,4}:){0,5}:((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|(::([0-9A-Fa-f]{1,4}:){0,5}((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))$%', $forwarded_for))
					$remote_addr = $forwarded_for;
			}
		}

		return $remote_addr;
	}

	/**
	 * get_user_avatar_url 
	 * 
	 * @param int $user_id 
	 * @access public
	 * @return string
	 */
	public function get_user_avatar_url($user_id) {
		$filetypes = array('jpg', 'gif', 'png');

		$pun_config = $this->get_pun_config();
		foreach ($filetypes as $cur_type)
		{
			$path = $pun_config['o_avatars_dir'].'/'.$user_id.'.'.$cur_type;

			if (file_exists(PUN_ROOT.$path) && $img_size = getimagesize(PUN_ROOT.$path))
				return $path;
		}
	}

	/**
	 * logout 
	 * 
	 * @access public
	 * @return void
	 */
	public function logout() {
		$pun_user = array();
		$this->check_cookie($pun_user);
		// Remove user from "users online" list
		$this->_db->query('DELETE FROM '.$this->_db->prefix.'online WHERE user_id='.$pun_user['id']);

		// Update last_visit (make sure there's something to update it with)
		if (isset($pun_user['logged']))
			$this->_db->query('UPDATE '.$this->_db->prefix.'users SET last_visit='.$pun_user['logged'].' WHERE id='.$pun_user['id']);

		//$this->setcookie(1, $this->pun_hash(uniqid(rand(), true)), time() + 31536000);
		$expire = time() + 31536000;
		$this->setcookie($this->_config['cookie_name'], '1|'.$this->forum_hmac($this->pun_hash(uniqid(rand(), true)), $this->_config['cookie_seed'].'_password_hash').'|'.$expire.'|'.$this->forum_hmac('1|'.$expire, $this->_config['cookie_seed'].'_cookie_hash'), $expire);
	}
	
	/**
	 * register 
	 * 
	 * @param mixed $user 
	 * @param mixed $password 
	 * @param mixed $email 
	 * @param mixed $timezone 
	 * @param mixed $usergroup 
	 * @access public
	 * @return void
	 */
	public function register($user, $password, $email, $timezone, $usergroup) {
		return;

		//TODO

		// Add the user
		//$password = $this->pun_hash($password);
		//$sql = "INSERT INTO `users` (`username`,`password`,`email`, `group_id`, `timezone`, `registered`,`registration_ip`)
				//VALUES('" .  $user . "', '" .  $password . " ', '" . $email . "', " . $usergroup . ", '" . $timezone . "', '" . time() . "', '" . $_SERVER['REMOTE_ADDR'] . "')";
		//$this->_db->query($sql);
		//$id = db_result(db_query("select max(id) from ".$forum_config['db_prefix']."users"));
		//drupal_set_message($sql);
	}

	//Updates all information that is set by fluxbb::register(). You cannont change the username yet, because it is used as a reference when searching the database
	/**
	 * update 
	 * 
	 * @param mixed $user 
	 * @param mixed $password 
	 * @param mixed $email 
	 * @param mixed $timezone 
	 * @static
	 * @access public
	 * @return void
	 */
	static function update($user, $password, $email, $timezone){
		return;

		//TODO

		//$result = $this->_db->query("SELECT * FROM users WHERE user ='" . $user . "'");
		//$row = $this->_db->fetch_assoc($result);
		//if(empty($password)){
			//$password = $row['password'];
		//}else{
			//$password = $this->pun_hash($password);
		//}
		//if(empty($email)){
			//$email = $row['email'];
		//}
		//if(empty($timezone)){
			//$timezone = $row['timezone'];
		//}
		//$sql = "UPDATE users SET password = '" . $password . "', email='" . $email . "', timezone='" . $timezone . "' WHERE username = '" . $user . "'";
		////drupal_set_message($sql);
		//$this->_db->query($sql);
	}

	/**
	 * check_cookie 
	 * 
	 * @param mixed $pun_user 
	 * @access public
	 * @return boolean false if user is not logged in fluxbb
	 */
	public function check_cookie(&$pun_user) {
		$now = time();

		// If the cookie is set and it matches the correct pattern, then read the values from it
		if (isset($_COOKIE[$this->_config['cookie_name']]) && preg_match('%^(\d+)\|([0-9a-fA-F]+)\|(\d+)\|([0-9a-fA-F]+)$%', $_COOKIE[$this->_config['cookie_name']], $matches))
		{
			$cookie = array(
				'user_id'			=> intval($matches[1]),
				'password_hash' 	=> $matches[2],
				'expiration_time'	=> intval($matches[3]),
				'cookie_hash'		=> $matches[4],
			);
		}

		// If it has a non-guest user, and hasn't expired
		if (isset($cookie) && $cookie['user_id'] > 1 && $cookie['expiration_time'] > $now) {
			// If the cookie has been tampered with
			if ($this->forum_hmac($cookie['user_id'].'|'.$cookie['expiration_time'], $this->_config['cookie_seed'].'_cookie_hash') != $cookie['cookie_hash'])
			{
				return false;
			}

			// Check if there's a user with the user ID and password hash from the cookie
			$result = $this->_db->query('SELECT u.*, g.*, o.logged, o.idle FROM '.$this->_db->prefix.'users AS u INNER JOIN '.$this->_db->prefix.'groups AS g ON u.group_id=g.g_id LEFT JOIN '.$this->_db->prefix.'online AS o ON o.user_id=u.id WHERE u.id='.intval($cookie['user_id'])) or error('Unable to fetch user information', __FILE__, __LINE__, $this->_db->error());
			$pun_user = $this->_db->fetch_assoc($result);

			// If user authorisation failed
			if (!isset($pun_user['id']) || $this->forum_hmac($pun_user['password'], $this->_config['cookie_seed'].'_password_hash') !== $cookie['password_hash'])
			{
				return false;
			}

			$pun_user['is_guest'] = false;
			$pun_user['is_admmod'] = $pun_user['g_id'] == 1 || $pun_user['g_moderator'] == '1';
			return true;
		}
		else
			return false;
	}
}
