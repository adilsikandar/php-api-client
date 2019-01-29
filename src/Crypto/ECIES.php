<?php
namespace Mifiel\Crypto;

use Mdanter\Ecc\EccFactory,
    Mdanter\Ecc\Crypto\Key\PublicKey,
    Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer,
    Mdanter\Ecc\Serializer\Point\CompressedPointSerializer,
    Mdanter\Ecc\Util\NumberSize;

class ECIES {
  private $digest_size = 256;
  private $digest = 'sha256';
  private $kdf_digest = 'sha512';
  private $cipher = 'AES-256-CBC';
  private $iv_size = 16;
  private $private_key;
  private $public_key;
  private $curve;
  private $adapter;
  private $generator;
  private $serializer;
  private $iv;
  private $ephemeral_public_key;
  private $ciphertext;
  private $mac;

  function __construct($params = null) {
    $adapter = EccFactory::getAdapter();
    $this->adapter = $adapter;
    $this->generator = EccFactory::getSecgCurves()->generator256k1();
    $this->curve = EccFactory::getSecgCurves()->curve256k1();
    $this->serializer = new CompressedPointSerializer($adapter);

    if (ctype_xdigit($params)) {
      $this->parseEncryptedMessage($params);
    } else if (is_array($params)) {
      $valid_attrs = [ 'iv', 'ephemeral_public_key', 'ciphertext', 'mac' ];
      foreach ($params as $attr => $value) {
        if (in_array($attr, $valid_attrs)) {
          $this->$attr = $value;
        }
      }
    } else if ($params !== null) {
      throw new \InvalidArgumentException("ECIES construct expects an (object)[] of params ([ 'iv', 'ephemeral_public_key', 'ciphertext', 'mac' ]) or the data as hex string.");
    }
  }

  public function setPrivateKey($hex_string) {
    $this->private_key = $this->getPrivateKeyFrom($hex_string);
  }

  public function setPublicKey($hex_string) {
    $this->public_key = $this->getPublicKeyFrom($hex_string);
  }

  public function encrypt($message) {
    if (empty($this->public_key)) {
      throw new \InvalidArgumentException('ECIES->encrypt: Before encrypting, set the public key with ECIES->setPublicKey($hex_key)');
    }
    if (empty($message)) {
      throw new \InvalidArgumentException('ECIES->encrypt: $message is required');
    }
    $ephemeral_key = $this->generator->createPrivateKey();
    $shared_secret = $ephemeral_key->createExchange($this->public_key)->calculateSharedKey();
    $derived_key = $this->keyDerivationFunction($shared_secret);
    $keys = $this->genCipherHmacKeys($derived_key);
    return $this->generateEncryptedMessage([
      'ephemeral_key' => $ephemeral_key,
      'hmac_key' => $keys['hmac_key'],
      'cipher_key' => $keys['cipher_key'],
      'message' => $message
    ]);
  }

  public function decrypt() {
    if (empty($this->private_key)) {
      throw new \InvalidArgumentException('ECIES->decrypt: Before decrypting, set the private key with ECIES->setPublicKey($hex_key)');
    }
    $ephemeral_pub_key = $this->getPublicKeyFrom($this->ephemeral_public_key);
    $shared_secret = $this->private_key->createExchange($ephemeral_pub_key)->calculateSharedKey();
    $derived_key = $this->keyDerivationFunction($shared_secret);
    $keys = $this->genCipherHmacKeys($derived_key);
    $partial = $this->iv . $this->ephemeral_public_key . $this->ciphertext;
    $computed_mac = $this->computeHmac($keys['hmac_key'], $partial);
    if ($computed_mac != $this->mac) {
      throw new \InvalidArgumentException('Invalid mac');
    }
    return openssl_decrypt(
      hex2bin($this->ciphertext),
      $this->cipher,
      hex2bin($keys['cipher_key']),
      true,
      hex2bin($this->iv)
    );
  }

  private function getDigestHexLen() {
    return $this->digest_size / 8 * 2;
  }

  private function computeHmac($key, $data) {
    if (ctype_xdigit($key)) {
      $key = hex2bin($key);
    }
    if (ctype_xdigit($data)) {
      $data = hex2bin($data);
    }
    return hash_hmac($this->digest, $data, $key);
  }

  private function genCipherHmacKeys($derived_key) {
    $digest_size = $this->getDigestHexLen();
    $hex_derived_key = bin2hex($derived_key);
    $cipher_key = substr($hex_derived_key, 0, $digest_size);
    $hmac_key = substr($hex_derived_key, $digest_size, $digest_size);
    return [
      'cipher_key' => $cipher_key,
      'hmac_key' => $hmac_key,
    ];
  }

  private function parseEncryptedMessage($encrypted_message) {
    $digest_size = $this->getDigestHexLen();
    $iv_hex_len = $this->iv_size * 2;
    $msg_len = strlen($encrypted_message);
    $ephemeral_type = substr($encrypted_message, $iv_hex_len, 2) === '04' ? 'uncompressed' : 'compressed';
    $ephemeral_pub_key_len = $ephemeral_type === 'compressed' ? 66 : 130;
    $ciphertext_len = $msg_len - $ephemeral_pub_key_len - $digest_size - $iv_hex_len;
    if ($ciphertext_len < 1) {
      throw new \InvalidArgumentException('Encrypted message too short');
    }
    $this->iv = substr($encrypted_message, 0, $iv_hex_len);
    $this->ephemeral_public_key = substr($encrypted_message, $iv_hex_len, $ephemeral_pub_key_len);
    $this->ciphertext = substr($encrypted_message, ($iv_hex_len + $ephemeral_pub_key_len), $ciphertext_len);
    $this->mac = substr($encrypted_message, strlen($encrypted_message) - $digest_size, $digest_size);
  }

  private function getPrivateKeyFrom($hex_string) {
    return $this->generator->getPrivateKeyFrom(gmp_init($hex_string, 16));
  }

  private function getPublicKeyFrom($hex_string) {
    $serializer = $this->serializer;
    if (substr($hex_string, 0, 2) === '04') {
      $serializer = new UncompressedPointSerializer($this->adapter);
    }
    $pub_key_point = $serializer->unserialize($this->curve, $hex_string);
    return new PublicKey($this->adapter, $this->generator, $pub_key_point);
  }

  private function keyDerivationFunction($shared_secret) {
    $generator = $this->generator;
    $adapter = $generator->getAdapter();
    $binary = $adapter->intToFixedSizeString(
      $shared_secret,
      NumberSize::bnNumBytes($adapter, $generator->getOrder())
    );
    return hash($this->kdf_digest, $binary, true);
  }

  private function generateEncryptedMessage($params) {
    $ephemeral_key = $params['ephemeral_key'];
    $hmac_key = $params['hmac_key'];
    $cipher_key = $params['cipher_key'];
    $message = $params['message'];
    $iv = openssl_random_pseudo_bytes($this->iv_size, $safe);
    $this->ephemeral_public_key = $this->serializer->serialize($ephemeral_key->getPublicKey()->getPoint());
    $this->ciphertext = bin2hex(openssl_encrypt($message, $this->cipher, hex2bin($cipher_key), true, $iv));
    $this->iv = bin2hex($iv);
    $partial = $this->iv . $this->ephemeral_public_key . $this->ciphertext;
    $this->mac = $this->computeHmac($hmac_key, $partial);
    return $partial . $this->mac;
  }
}
