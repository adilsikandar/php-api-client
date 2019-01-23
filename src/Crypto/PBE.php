<?php
namespace Mifiel\Crypto;

class PBE {
  private $num_iterations = 1000;
  private $digest_algorithm = 'sha256';

  function __construct($params = null) {
    if (is_array($params)) {
      if (array_key_exists('iterations', $params)) {
        $this->num_iterations = $params['iterations'];
      }
      if (array_key_exists('digestAlgorithm', $params)) {
        $this->digest_algorithm = $params['digestAlgorithm'];
      }
    } else if ($params !== null) {
      throw new \InvalidArgumentException('PBE construct expects an (object)[] of params');
    }
  }

  public function setIterations($num) {
    $this->num_iterations = $num;
  }

  public function getIterations() {
    return $this->num_iterations;
  }

  public function setDigestAlgorithm($alg) {
    $this->digest_algorithm = $alg;
  }

  public function getDigestAlgorithm() {
    return $this->digest_algorithm;
  }

  public static function randomPassword($length = 32) {
    $password = '';
    while (strlen($password) < $length) {
      $randomBytes = openssl_random_pseudo_bytes(100, $safe);
      $password .= preg_replace('/[^\x20-\x7E]/', '', $randomBytes);
    }
    return substr($password, 0, $length);
  }

  public static function randomSalt($size = 16) {
    return openssl_random_pseudo_bytes($size, $safe);
  }

  public function getDerivedKey($params) {
    $size = empty($params['size']) ? 32 : $params['size'];
    $salt = empty($params['salt']) ? '' : $params['salt'];
    $password =  $params['password'];
    if ($size > 1000) {
      throw new \InvalidArgumentException('key lenght/size requested is too long');
    }
    if (ctype_xdigit($salt)) {
      $salt = hex2bin($salt);
    }
    return hash_pbkdf2($this->digest_algorithm, $password, $salt, $this->num_iterations, $size * 2);
  }
}
