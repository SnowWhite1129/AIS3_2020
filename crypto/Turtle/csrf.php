<?php

    class Csrf {
        private $secret, $key, $size;
        
        function __construct($key) {
            $this->key = $key;
            $this->secret = file_get_contents('/turtle.flag');
            $this->size = openssl_cipher_iv_length('aes-256-cbc');
        }
        
        function generate() {
            $iv = openssl_random_pseudo_bytes($this->size);
            $cipher = openssl_encrypt($this->secret, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $iv);
            $token = base64_encode($iv . $cipher);
            return $token;
        }
        
        function validate($token) {
            $bytes = base64_decode($token);
            $iv = substr($bytes, 0, $this->size); // extract IV
            $cipher = substr($bytes, $this->size); // extract cipher
            $secret = openssl_decrypt($cipher, 'aes-256-cbc', $this->key, OPENSSL_RAW_DATA, $iv);
            if ($secret === false)
                throw new Exception('token decryption failed');
            return $secret === $this->secret;
        }    
    }

    if (basename(__FILE__) == basename($_SERVER["SCRIPT_FILENAME"])) {
        // called directly

        if (isset($_GET['source'])) {
            highlight_file(__FILE__);
        }
        exit;
    }
