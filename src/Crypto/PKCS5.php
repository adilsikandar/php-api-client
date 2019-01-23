<?php
namespace Mifiel\Crypto;

use FG\ASN1\Object as ASNObject,
    FG\ASN1\Universal\Integer as ASNInteger,
    FG\ASN1\Universal\ObjectIdentifier,
    FG\ASN1\Universal\OctetString,
    FG\ASN1\Universal\Sequence,
    FG\ASN1\UnknownObject;

class PKCS5 {
  const PKCS5_OID = '1.2.840.113549.1.5.13';
  const PBKDF2_OID = '1.2.840.113549.1.5.12';
  const HMAC_SHA256_OID = '1.2.840.113549.2.9';
  const AES_128_CBC_OID = '2.16.840.1.101.3.4.1.2';
  const AES_192_CBC_OID = '2.16.840.1.101.3.4.1.22';
  const AES_256_CBC_OID = '2.16.840.1.101.3.4.1.42';

  private $key_size;
  private $iv;
  private $salt;
  private $iterations;
  private $cipher_data;

  function __construct($params = null) {
    if (is_array($params)) {
      $valid_attrs = [ 'key_size', 'iv', 'salt', 'iterations', 'cipher_data' ];
      foreach ($params as $attr => $value) {
        if (in_array($attr, $valid_attrs)) {
          $this->$attr = $value;
        }
      }
    } else if ($params !== null) {
      throw new \InvalidArgumentException('PBE construct expects an (object)[] of params');
    }
  }

  public function __get($property) {
    if (property_exists($this, $property)) {
        return $this->$property;
    }
  }

  public static function getSupportedAlghoritms() {
    return [
      self::AES_128_CBC_OID,
      self::AES_192_CBC_OID,
      self::AES_256_CBC_OID ,
    ];
  }

  public static function getCipherId($key_size) {
    if (empty($key_size)) {
      throw new \InvalidArgumentException('PKCS5->getCipherId : $key_size is required and must be a supported key length.');
    }
    switch ($key_size) {
      case 128:
        return self::AES_128_CBC_OID;
      case 192:
        return self::AES_192_CBC_OID;
      case 256:
        return self::AES_256_CBC_OID;
      default:
        throw new \InvalidArgumentException('AES cipher key length not supported.');
    }
  }

  public function getKeySizeBytes() {
    switch($this->key_size) {
      case self::AES_128_CBC_OID:
        return 16;
      case self::AES_192_CBC_OID:
        return 24;
      case self::AES_256_CBC_OID:
        return 32;
    }
  }

  public function loadASN1($binary_data) {
    if (ctype_xdigit($binary_data)) {
      $binary_data = hex2bin($binary_data);
    }
    try {
      $asn_object = ASNObject::fromBinary($binary_data);
      $this->validateLoadedASN1($asn_object);
      $asnL1 = $asn_object[0][1][0];
      $asnL2 = $asn_object[0][1][1];
      $this->key_size = $asnL2[0]->getContent();
      $this->iv = $asnL2[1]->getContent();
      $this->salt = $asnL1[1][0]->getContent();
      $this->iterations = $asnL1[1][1]->getContent();
      $this->cipher_data = $asn_object[1]->getContent();
    } catch (Exception $e) {
      throw new \InvalidArgumentException($e->getMessage());
    }
  }

  public function ASN1() {
    $this->validateASN1Gen();
    $seq = new Sequence(
      new Sequence(
        new ObjectIdentifier(self::PKCS5_OID),
        new Sequence(
          new Sequence(
            new ObjectIdentifier(self::PBKDF2_OID),
            new Sequence(
              new OctetString($this->salt),
              new ASNInteger($this->iterations),
              new Sequence(
                new ObjectIdentifier(self::HMAC_SHA256_OID)
              )
            )
          ),
          new Sequence(
            new ObjectIdentifier(self::getCipherId($this->key_size)),
            new OctetString($this->iv)
          )
        )
      ),
      new OctetString($this->cipher_data)
    );
    return $seq->getBinary();
  }

  private function validateLoadedASN1($asn_object) {
    if ($asn_object instanceof UnknownObject) {
      throw new \Exception('Exception decoding bytes: Bytes are not PKCS5.');
    }
    $pkcs_identifier = $asn_object[0][0]->getContent();
    if ($pkcs_identifier !== self::PKCS5_OID) {
      throw new \Exception('Exception decoding bytes: Bytes are not PKCS5.');
    }
    $pbkdf2_identifier = $asn_object[0][1][0][0]->getContent();
    if ($pbkdf2_identifier !== self::PBKDF2_OID) {
      throw new \Exception('Exception decoding bytes: Bytes are not pkcs5PBKDF2.');
    }
    $supported_algs = self::getSupportedAlghoritms();
    $key_size = $asn_object[0][1][1][0]->getContent();
    if (!in_array($key_size, $supported_algs)) {
      throw new \Exception('Encryption algorithm not supported.');
    }
    $digest_alg = $asn_object[0][1][0][1][2][0]->getContent();
    if ($digest_alg !== self::HMAC_SHA256_OID) {
      throw new \Exception('Digest algorithm not supported.');
    }
  }

  private function validateASN1Gen() {
    $required_props = [
      'key_size',
      'iv',
      'salt',
      'iterations',
      'cipher_data',
    ];
    foreach ($required_props as $prop) {
      if (!isset($this->$prop)) throw new \Exception($prop . 'must be set before getting the ASN.1 notation', 1);
    }
  }
}
