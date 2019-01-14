<?php
namespace Mifiel;

use Virgil\CryptoImpl\VirgilCrypto;

class EC {
  private $digest = 'sha512';
  private $cipher = 'AES-256-CBC';
  // function __construct($params = null) {
  //   if (is_array($params)) {
  //     if (array_key_exists('blockSize', $params)) {
  //       $this->blockSize = $params['blockSize'];
  //     }
  //   } else if ($params !== null) {
  //     throw new \InvalidArgumentException('AES construct expects an (object)[] of params');
  //   }
  // }

  public static function encrypt() {
    $iv = openssl_random_pseudo_bytes(16, $safe);
    $encryptedData = openssl_encrypt($data, $this->cipher, $password, true, $iv);
    return hash_pbkdf2($this->digest, $password, $salt, $this->numIterations, $size * 2);
  }
}
