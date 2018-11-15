<?php
namespace Mifiel;

class AES {
  private $blockSize = 192;

  function __construct($params = null) {
    if (is_array($params)) {
      if (array_key_exists('blockSize', $params)) {
        $this->blockSize = $params['blockSize'];
      }
    } else if ($params !== null) {
      throw new \InvalidArgumentException('AES construct expects an (object)[] of params');
    }
  }

  public function setBlockSize($size = 192) {
    $this->blockSize = $size;
  }

  public function getBlockSize() {
    return $this->blockSize;
  }

  public function getAlgorithm() {
    return 'AES-'.$this->blockSize.'-CBC';
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
    $encryptedData = openssl_encrypt($data, $this->getAlgorithm(), $password, true, $iv);
    return [
      'encrypted_data' => bin2hex($encryptedData),
      'iv' => $iv,
    ];
  }

  public function decrypt($encryptedData, $password, $iv) {
    if (mb_detect_encoding($encryptedData) !== false) {
      $encryptedData = hex2bin($encryptedData);
    }
    if (mb_detect_encoding($iv) !== false) {
      $iv = hex2bin($iv);
    }
    return openssl_decrypt($encryptedData, $this->getAlgorithm(), $password, true, $iv);
  }
}
