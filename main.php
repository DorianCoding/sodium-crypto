<?php
namespace Cryptography;
    class PasswordCryptography {
        /* No object on this class
         * Hashed password is returned by gethash() function (static function)
         * Checkpassword check a password against a hash (static function) and return a bool (true if valid, false else)
         * Encode and decode allows to manipulate crypto elements in a visible manner (bytes to base64)
         */
        static public function gethash($pass) : string {
            return sodium_crypto_pwhash_str($pass, SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE);
        }
        static public function checkpassword(string $password, string $hash) : bool {
            return sodium_crypto_pwhash_str_verify($hash, $password);
        }
        static public function encode(string $text) : string {
            return sodium_bin2base64($text, SODIUM_BASE64_VARIANT_URLSAFE);
        }
        static public function decode(string $text) : string {
            return sodium_base642bin($text, SODIUM_BASE64_VARIANT_URLSAFE);
        }
    }
    class Blockchain {
        /* A blockchain function, using Ed25519 keys and leading zeros hash to perform an authentification (sha256).
         * Construct create a new keypair (public and private key). Accessible by getKey function.
         * Sign allows to sign a text using a privatekey (static function) - detached. Returns a string.
         * Checksign allows to verify the integrity of a text with the detached signature (from sign) using the sender publickey (static function). Returns a bool.
         * Getleadingzeros is using an hashing method to perform a proof-of-work (may take some time according to configuration) on the message to add to the blockchain.
         */
        private $keys;
        function __construct() {
            $this->keys=sodium_crypto_sign_keypair();
        }
        function getKey($private=false) : string {
            if (!$private) {
                return PasswordCryptography::encode(sodium_crypto_sign_publickey($this->keys));
            } else {
                return PasswordCryptography::encode(sodium_crypto_sign_secretkey($this->keys));
            }
        }
        static function sign($text, $privatekey) {
            return PasswordCryptography::encode(sodium_crypto_sign_detached($text,PasswordCryptography::decode($privatekey)));
        }
        static function checksign($text,$signature,$publickey) : bool {
            return sodium_crypto_sign_verify_detached(PasswordCryptography::decode($signature), PasswordCryptography::decode($text),PasswordCryptography::decode($publickey));
        }
        static function getleadingzeroshash($text,$privatekey, $add=5,$leadingzeros=5) {
            $hash="";
            if ($leadingzeros>63) {
                return false;
            }
            while (substr($hash, $leadingzeros)===str_repeat("0", $leadingzeros)) {
                $hash=hash("sha256",$text . bin2hex(random_bytes($add)),false);
            }
            $verify=Blockchain::sign($text . $hash,$key);
            return [$hash, $verify];
        }
    }
    class AsymetricCryptography {
        /* 
         * Construct creates or takes an  X25519 keypair.
         * Getkey allows to get the rsakey.
         * Encrypt allows to encrypt a message using public key of receiver. Integrity can also be performed signing with sender private key.
         * Decrypt allows to decrypt a message using receiver private key. Integrity can also be performed checking for sender public key.
         */
        protected $rsakey;
        protected $nonce;
        function __construct($key="") {
            if (!is_string($key)) {
                throw new \Exception("key is not a valid format.");
            }
            if (!empty($key)) {
                $this->rsakey=PasswordCryptography::decode($key);
            } else {
                $this->rsakey=sodium_crypto_box_keypair();
            }
        }
        function getkey($private = False) {
            if ($private) {
                return array(
                    "private" -> PasswordCryptography::encode(sodium_crypto_box_secretkey($this->rsakey)),
                    "public" -> PasswordCryptography::encode(sodium_crypto_box_publickey($this->rsakey))
                    );
            } else {
                return PasswordCryptography::encode(sodium_crypto_box_publickey($this->rsakey));
            }
        }
        function encrypt($text,$authentificated= False, $privatekey = null) : array {
            if (!$authentificated) {
                $publickey=sodium_crypto_box_publickey($this->rsakey);
                return PasswordCryptography::encode(sodium_crypto_box_seal($text, $publickey));
            } else {
                $key=sodium_crypto_box_keypair_from_secretkey_and_publickey(sodium_crypto_box_secretkey(PasswordCryptography::decode($privatekey)),sodium_crypto_box_publickey($this->rsakey));
                $val=false;
                $nonce=openssl_random_pseudo_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES, $val);
                if (!$val) {
                    $nonce=random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
                }
                return array(
                    "nonce" => PasswordCryptography::encode($nonce),
                    "message" => PasswordCryptography::encode(sodium_crypto_box($text, $nonce, $key))
                );
            }
        }
        function decrypt($text,$authentificated= False, $publickey = null, $nonce= null) {
            if (!$authentificated) {
                $privatekey=sodium_crypto_box_secretkey($this->rsakey);
                return sodium_crypto_box_seal_open(PasswordCryptography::decode($text), PasswordCryptography::decode($privatekey));
            } else {
                $key=sodium_crypto_box_keypair_from_secretkey_and_publickey(sodium_crypto_box_publickey(PasswordCryptography::decode($publickey)),sodium_crypto_box_secretkey($this->rsakey));
                if (!strlen($nonce)!==SODIUM_CRYPTO_BOX_NONCEBYTES) {
                    throw new \Exception("Error with the nonce.");
                }
                return sodium_crypto_box_open(PasswordCryptography::decode($text), PasswordCryptography::decode($nonce), $key);
            }
        }
    }
    class AEScryptography {
        /* 
         * FOR SECURITY, INITIATE THE FUNCTION FOR EACH ENCRYPTION BLOCK.
         * Construct creates a AES256 key (symetric encryption) and a nonce.
         * Encrypt allows to encrypt a message and a nonce.
         * Decrypt allows to decrypt a message using key/nonce.
         * Getkey and getnonce respectively gives key and nonce.
         */
        protected $aeskey;
        protected $nonce;
        public function __construct($key = null, $nonce=null) {
            if (sodium_crypto_aead_aes256gcm_is_available()) { //Si l'AES est disponible
                if (empty($key)) {
                    $this->aeskey=sodium_crypto_aead_aes256gcm_keygen();
                } else {
                    $this->aeskey=PasswordCryptography::decode($key);
                }
            } else {
                throw new \Exception("Secure aes not exist");
            }
            if (!empty($nonce)) {
                $this->nonce=$nonce;
                return;
            }
            $val=false;
            $this->nonce=openssl_random_pseudo_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES, $val);
            if (!$val) {
                $this->nonce=random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
            }
        }
        public function encrypt($text) : string {
            return PasswordCryptography::encode(sodium_crypto_aead_aes256gcm_encrypt($text, "",$this->nonce,$this->aeskey));
        }
        public function decrypt($ciphertext, $nonce = null) {
            if (!empty($nonce)) {
                $this->nonce=PasswordCryptography::decode($nonce);
            }
            return sodium_crypto_aead_aes256gcm_decrypt(PasswordCryptography::decode($ciphertext), "",$this->nonce,$this->aeskey);
        }
        public function getkey() {
            return PasswordCryptography::encode($this->aeskey);
        }
        public function getnonce() {
            return PasswordCryptography::encode($this->nonce);
        }
    }
   }
   ?>
