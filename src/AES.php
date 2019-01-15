<?php
namespace Mifiel;

class AES {
  private $block_size = 192;

  function __construct($params = null) {
    if (is_array($params)) {
      if (array_key_exists('blockSize', $params)) {
        $this->block_size = $params['blockSize'];
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

  public function encrypt($data, $password, $iv) {
    if ($iv === null) {
      $iv = $this->randomIV();
    }
    if (mb_detect_encoding($iv) !== false) {
      $iv = hex2bin($iv);
    }
    $encrypted_data = openssl_encrypt($data, $this->getAlgorithm(), $password, true, $iv);
    return [
      'encrypted_data' => bin2hex($encrypted_data),
      'iv' => $iv,
    ];
  }

  public function decrypt($encrypted_data, $password, $iv) {
    if (mb_detect_encoding($encrypted_data) !== false) {
      $encrypted_data = hex2bin($encrypted_data);
    }
    if (mb_detect_encoding($iv) !== false) {
      $iv = hex2bin($iv);
    }
    return openssl_decrypt($encrypted_data, $this->getAlgorithm(), $password, true, $iv);
  }
}
