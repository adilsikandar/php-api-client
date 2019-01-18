<?php
namespace Mifiel\Crypto;

use Elliptic\EC as ECC;

class EC {
  private $digest_size = 256;
  private $digest = 'sha256';
  private $kdf_digest = 'sha512';
  private $cipher = 'AES-256-CBC';
  private $iv_size = 16;
  private $ephem_pub_bytes_len = 65;
  private $ec;

  function __construct() {
    $this->ec = new ECC('secp256k1');
  }

  private function getDigestHexLen() {
    return $this->digest_size / 8 * 2;
  }

  private function genCipherHmacKeys($shared_secret) {
    $digest_size = $this->getDigestHexLen();
    $key_base = hash($this->kdf_digest, hex2bin($shared_secret));
    $cipher_key = substr($key_base, 0, $digest_size);
    $hmac_key = substr($key_base, $digest_size, $digest_size);
    return [
      'cipher_key' => $cipher_key,
      'hmac_key' => $hmac_key,
    ];
  }

  private function splitEncryptedMessage($encrypted_message) {
    $digest_size = $this->getDigestHexLen();
    $iv_hex_len = $this->iv_size * 2;
    $msg_len = strlen($encrypted_message);
    $iv = substr($encrypted_message, 0, $iv_hex_len);
    $ephemeral_pub_key_len = $this->ephem_pub_bytes_len * 2;
    $ephemeral_pub_key = substr($encrypted_message, $iv_hex_len, $ephemeral_pub_key_len);
    $ciphertext_len = $msg_len - $ephemeral_pub_key_len - $digest_size - $iv_hex_len;
    if ($ciphertext_len < 1) {
      throw new \InvalidArgumentException('Encrypted message too short');
    }
    $ciphertext = substr($encrypted_message, ($iv_hex_len + $ephemeral_pub_key_len), $ciphertext_len);
    $mac = substr($encrypted_message, strlen($encrypted_message) - $digest_size, $digest_size);
    return [
      'iv' => $iv,
      'ephemeral_public_key' => $ephemeral_pub_key,
      'ciphertext' => $ciphertext,
      'mac' => $mac,
    ];
  }

  public function encrypt($public_key, $message) {
    if ($public_key === null || $message === null) {
      throw new \InvalidArgumentException('EC->encrypt: Both params ($public_key, $message) are required');
    }
    $iv = openssl_random_pseudo_bytes($this->iv_size, $safe);
    $key = $this->ec->keyFromPublic(hex2bin($public_key));
    $ephemeral_key = $this->ec->genKeyPair();
    $shared_secret = $ephemeral_key->derive($key->getPublic())->toString(16);
    $keys = $this->genCipherHmacKeys($shared_secret);
    $ciphertext = bin2hex(openssl_encrypt($message, $this->cipher, hex2bin($keys['cipher_key']), true, $iv));
    $partial = bin2hex($iv) . $ephemeral_key->getPublic('hex') . $ciphertext;
    $mac = hash_hmac($this->digest, hex2bin($partial), hex2bin($keys['hmac_key']));
    return $partial . $mac;
  }

  public function decrypt($private_key, $encrypted_message) {
    if ($private_key === null || $encrypted_message === null) {
      throw new \InvalidArgumentException('EC->decrypt: Both params ($private_key, $encrypted_message) are required');
    }
    $key = $this->ec->keyFromPrivate($private_key);
    $enc_data = $this->splitEncryptedMessage($encrypted_message);
    $iv = $enc_data['iv'];
    $ephemeral_public_key = $enc_data['ephemeral_public_key'];
    $ciphertext = $enc_data['ciphertext'];
    $mac = $enc_data['mac'];
    $ephemeral_key = $this->ec->keyFromPublic(hex2bin($ephemeral_public_key));
    $shared = $key->derive($ephemeral_key->getPublic())->toString(16);
    $keys = $this->genCipherHmacKeys($shared);
    $partial = $iv . $ephemeral_public_key . $ciphertext;
    $computed_mac = hash_hmac($this->digest, hex2bin($partial), hex2bin($keys['hmac_key']));
    if ($computed_mac != $mac) {
      throw new \InvalidArgumentException('Invalid mac');
    }
    return openssl_decrypt(hex2bin($ciphertext), $this->cipher, hex2bin($keys['cipher_key']), true, hex2bin($iv));
  }
}
