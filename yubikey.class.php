<?php
define('OTP_LENGTH', 16);
define('YUBI_LENGTH', 32);
define('MODHEX_DICT', 'cbdefghijklnrtuv');
define('HEX_DICT', '0123456789abcdef');
define('OTP_CIPHER', 'aes-128-ecb');

class YubiOTP
{
	function __construct($rawstr) {
		/**
		 * Yubikey data layout, see "Technical documentation" at
		 * http://www.yubico.com/support/documentation/
		 *
		 * Offset  Name 		    Format
		 * 0       Private ID       6 bytes
		 * 6       Usage counter    16-bit LE integer 
		 * 8       Timestamp        24-bit LE integer
		 * 11      Session counter  8 bit LE integer
		 * 12      Random number    16-bit LE integer
		 * 14      CRC              16-bit LE integer
		 */
		if (strlen($rawstr) != OTP_LENGTH)
			throw new Exception('Bad length input');

		$fields = unpack("a6id/vusage/vtstamp_lo/Ctstamp_hi/Csession/vrandom/vcrc", $rawstr);
		if ($fields === false)
			throw new Exception("Malformed OTP data");
		
		$this->id = bin2hex($fields['id']);
		$this->external_trigger = !!($fields['usage'] & 0x8000);
		$this->usage_counter = $fields['usage'] & 0x7fff;
		$this->timestamp = $fields['tstamp_lo'] + ($fields['tstamp_hi'] >> 16);
		$this->session_counter = $fields['session'];
		$this->random_number = $fields['random'];
		$this->crc = $fields['crc'];		

		$this->input = $rawstr;
	}

	public function validChecksum() {
		$checksum = 0xffff;

		for ($i = 0; $i < strlen($this->input); $i++) {
			$checksum ^= ord($this->input[$i]);
			for ($j = 0; $j < 8; $j++) {
				$n = $checksum & 1;
				$checksum >>= 1;
				if ($n)
					$checksum ^= 0x8408;
			}
		}

		return ($checksum == 0xf0b8);
	}
}

class YubiParser
{
	private static function mod2hex($modhex) {
		return strtr($modhex, MODHEX_DICT, HEX_DICT);
	}

	function __construct($rawstr) {
		$len = strlen($rawstr);

		if ($len < YUBI_LENGTH)
			throw new Exception('Invalid OTP string');
		
		if ($len > YUBI_LENGTH) {
			$this->identity = substr($rawstr, 0, $len - YUBI_LENGTH);
			$cipher = substr($rawstr, $len - YUBI_LENGTH);
		} else {
			$this->identity = null;
			$cipher = $rawstr;
		}
		$this->encrypted_otp = hex2bin($this->mod2hex($cipher));
	}
	
	public function getIdentity() {
		return $this->identity;
	}
	
	public function getOTP($decryptionkey) {			
		if (!in_array(OTP_CIPHER, openssl_get_cipher_methods()))
			throw new Exception('Unsupported cipher method AES-128');

		$decrypted = openssl_decrypt($this->encrypted_otp, OTP_CIPHER,
			$decryptionkey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);

		return new YubiOTP($decrypted);
	}
}

?>
