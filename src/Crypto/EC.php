<?php
namespace Mifiel\Crypto;

use Mdanter\Ecc\EccFactory,
    Mdanter\Ecc\Crypto\Key\PublicKey,
    Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer,
    Mdanter\Ecc\Serializer\Point\CompressedPointSerializer,
    Mdanter\Ecc\Util\NumberSize;

class EC {
  private $digest_size = 256;
  private $digest = 'sha256';
  private $kdf_digest = 'sha512';
  private $cipher = 'AES-256-CBC';
  private $iv_size = 16;
  private $curve;
  private $adapter;
  private $generator;
  private $serializer;

  function __construct() {
    $adapter = EccFactory::getAdapter();
    $this->adapter = $adapter;
    $this->generator = EccFactory::getSecgCurves()->generator256k1();
    $this->curve = EccFactory::getSecgCurves()->curve256k1();
    $this->serializer = new CompressedPointSerializer($adapter);
  }

  public function encrypt($public_key, $message) {
    if ($public_key === null || $message === null) {
      throw new \InvalidArgumentException('EC->encrypt: Both params ($public_key, $message) are required');
    }
    $public_key = $this->getPublicKeyFrom($public_key);
    $ephemeral_key = $this->generator->createPrivateKey();
    $shared_secret = $ephemeral_key->createExchange($public_key)->calculateSharedKey();
    $derived_key = $this->keyDerivationFunction($shared_secret);
    $keys = $this->genCipherHmacKeys($derived_key);

    $iv = openssl_random_pseudo_bytes($this->iv_size, $safe);
    $ephemeral_pub_key_hex = $this->serializer->serialize($ephemeral_key->getPublicKey()->getPoint());
    $ciphertext = bin2hex(openssl_encrypt($message, $this->cipher, hex2bin($keys['cipher_key']), true, $iv));
    $partial = bin2hex($iv) . $ephemeral_pub_key_hex . $ciphertext;
    $mac = hash_hmac($this->digest, hex2bin($partial), hex2bin($keys['hmac_key']));
    return $partial . $mac;
  }

  public function decrypt($private_key, $encrypted_message) {
    if ($private_key === null || $encrypted_message === null) {
      throw new \InvalidArgumentException('EC->decrypt: Both params ($private_key, $encrypted_message) are required');
    }
    $enc_data = $this->splitEncryptedMessage($encrypted_message);
    $iv = $enc_data['iv'];
    $ephemeral_pub_key_hex = $enc_data['ephemeral_public_key'];
    $ciphertext = $enc_data['ciphertext'];
    $mac = $enc_data['mac'];

    $key = $this->getPrivateKeyFrom($private_key);
    $ephemeral_pub_key = $this->getPublicKeyFrom($ephemeral_pub_key_hex);
    $shared_secret = $key->createExchange($ephemeral_pub_key)->calculateSharedKey();
    $derived_key = $this->keyDerivationFunction($shared_secret);
    $keys = $this->genCipherHmacKeys($derived_key);
    $partial = $iv . $ephemeral_pub_key_hex . $ciphertext;
    $computed_mac = hash_hmac($this->digest, hex2bin($partial), hex2bin($keys['hmac_key']));
    if ($computed_mac != $mac) {
      throw new \InvalidArgumentException('Invalid mac');
    }
    return openssl_decrypt(hex2bin($ciphertext), $this->cipher, hex2bin($keys['cipher_key']), true, hex2bin($iv));
  }

  private function getDigestHexLen() {
    return $this->digest_size / 8 * 2;
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

  private function splitEncryptedMessage($encrypted_message) {
    $digest_size = $this->getDigestHexLen();
    $iv_hex_len = $this->iv_size * 2;
    $msg_len = strlen($encrypted_message);
    $iv = substr($encrypted_message, 0, $iv_hex_len);
    $ephemeral_type = substr($encrypted_message, $iv_hex_len, 2) === '04' ? 'uncompressed' : 'compressed';
    $ephemeral_pub_key_len = $ephemeral_type === 'compressed' ? 66 : 130;
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
}
