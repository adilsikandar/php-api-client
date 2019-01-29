<?php
namespace Mifiel;

use Mifiel\Crypto\PBE,
    Mifiel\Crypto\AES,
    Mifiel\Crypto\ECIES,
    Mifiel\Crypto\PKCS5;

class Document extends BaseObject {
  protected static $resourceName = 'documents';
  protected $multipart = true;

  public function save() {
    unset($this->values->file);
    if (isset($this->values->file_path)) {
      $this->prepareFileToBeStored();
    }
    if (isset($this->values->shared_secret)) {
      $shared_secret = $this->values->shared_secret;
    }
    parent::save();
    if (isset($this->values->encrypted) && $this->values->encrypted) {
      $this->cipherSecretForSigners($shared_secret);
    }
  }

  public function saveFile($path) {
    $response = ApiClient::get(
      static::$resourceName . '/' . $this->id . '/file'
    );
    file_put_contents($path, $response->getBody());
  }

  public function saveFileSigned($path) {
    $response = ApiClient::get(
      static::$resourceName . '/' . $this->id . '/file_signed'
    );
    file_put_contents($path, $response->getBody());
  }

  public function saveXML($path) {
    $response = ApiClient::get(
      static::$resourceName . '/' . $this->id . '/xml'
    );
    file_put_contents($path, $response->getBody());
  }

  private function encryptFile() {
    $aes = new AES(['block_size' => 256]);
    $pbe = new PBE(['iterations' => 1000]);
    $salt = PBE::randomSalt();
    $random_password = PBE::randomPassword();
    $derived_key = $pbe->getDerivedKey([
      'salt' => $salt,
      'password' => $random_password,
    ]);
    $file_contents = file_get_contents($this->values->file_path);
    $encrypted_doc = $aes->encrypt([
      'data' => $file_contents,
      'password' => hex2bin($derived_key),
    ]);
    $pkcs5 = new PKCS5([
      'key_size' => 256,
      'iv' => $encrypted_doc['iv'],
      'salt' => bin2hex($salt),
      'iterations' => 1000,
      'cipher_data' => $encrypted_doc['encrypted_data'],
    ]);
    $this->values->shared_secret = $random_password;
    return $pkcs5->ASN1();
  }

  private function prepareFileToBeStored() {
    if (empty($this->values->encrypted)) {
      $file_contents = fopen($this->file_path, 'r');
    } else {
      $file_contents = $this->encryptFile();
    }
    $this->file = [
      'filename' => basename($this->file_path),
      'contents' => $file_contents,
    ];
    unset($this->values->file_path);
  }

  private function cipherSecretForSigners($secret) {
    $ec = new ECIES();
    $signatories = [];
    foreach ($this->values->signers as $key => $signer) {
      $map_f = function($public_key) use(&$ec, &$secret) {
        $ec->setPublicKey($public_key);
        return $ec->encrypt($secret);
      };
      $signatory_epwds = array_map($map_f ,$signer->pubs);
      array_push($signatories, ['id' => $signatory_epwds]);
    }
    $this->values->signatories = $signatories;
    parent::save();
  }
}
