<?php
namespace Mifiel;

class AES {
  private $algorithm = 'AES-192-CBC';

  function __construct($params = array()) {
    if (is_array($params)) {
      foreach ($params as $property => $value) {
        if (property_exists($this, $property)) {
          $this->$property = $value;
        }
      }
    }
  }

  public function __get($property) {
    if (property_exists($this, $property)) {
      return $this->$property;
    }
  }

  public function __set($property, $value) {
    if (property_exists($this, $property)) {
      $this->$property = $value;
    }
    return $this;
  }

  public static function randomIV($size = 16) {
    if ($size < 16) {
      throw new \InvalidArgumentException('IV lenght/size requested is too small, at least 16 is encouraged');
    }
    return openssl_random_pseudo_bytes($size, $safe);
  }
}
