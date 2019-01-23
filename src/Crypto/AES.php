<?php
namespace Mifiel\Crypto;

class AES {
  private $block_size = 192;

  function __construct($params = null) {
    if (is_array($params)) {
      if (array_key_exists('block_size', $params)) {
        $this->block_size = $params['block_size'];
      }
    } else if ($params !== null) {
      throw new \InvalidArgumentException('AES construct expects an (object)[] of params');
    }
  }

  public function setBlockSize($size = 192) {
    $this->block_size = $size;
  }

  public function getBlockSize() {
    return $this->block_size;
  }

  public function getAlgorithm() {
    return 'AES-'.$this->block_size.'-CBC';
  }

  public static function randomIV($size = 16) {
    if ($size < 16) {
      throw new \InvalidArgumentException('IV lenght/size requested is too small, at least 16 is encouraged');
    }
    return openssl_random_pseudo_bytes($size, $safe);
  }

  public function encrypt($params) {
    $error = $this->validateEncryptDecryptParams($params, 'encrypt');
    if (isset($error)) {
      throw $error;
    }
    $iv = empty($params['iv']) ? $iv = self::randomIV() : $params['iv'];
    $data = $params['data'];
    $password = $params['password'];
    if (ctype_xdigit($iv)) {
      $iv = hex2bin($iv);
    }
    $encrypted_data = openssl_encrypt($data, $this->getAlgorithm(), $password, true, $iv);
    return [
      'iv' => bin2hex($iv),
      'encrypted_data' => bin2hex($encrypted_data),
    ];
  }

  public function decrypt($params) {
    $error = $this->validateEncryptDecryptParams($params, 'decrypt');
    if (isset($error)) {
      throw $error;
    }
    $iv = $params['iv'];
    $data = $params['data'];
    $password = $params['password'];
    if (ctype_xdigit($data)) {
      $data = hex2bin($data);
    }
    if (ctype_xdigit($iv)) {
      $iv = hex2bin($iv);
    }
    return openssl_decrypt($data, $this->getAlgorithm(), $password, true, $iv);
  }

  private function validateEncryptDecryptParams($params, $caller) {
    if ($caller === 'decrypt' && empty($params['iv'])) {
      return new \InvalidArgumentException('AES->' . $caller . ' : [iv] is required in parameters.');
    } else if (empty($params['data'])) {
      return new \InvalidArgumentException('AES->' . $caller . ' : [data] is required in parameters.');
    } else if (empty($params['password'])) {
      return new \InvalidArgumentException('AES->' . $caller . ' : [password] is required in parameters.');
    }
  }
}
