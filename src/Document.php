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
    $encrypted_tmp_flag = false;
    unset($this->values->file);
    if (isset($this->values->file_path)) {
      $this->prepareFileToBeStored();
    }
    if (isset($this->values->shared_secret)) {
      $encrypted_tmp_flag = true;
      $shared_secret = $this->values->shared_secret;
    }
    parent::save();
    if ($encrypted_tmp_flag) {
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
    $filename = basename($this->file_path);
    if (empty($this->values->encrypted)) {
      $file_contents = fopen($this->file_path, 'r');
    } else {
      $filename .= '.enc';
      $file_contents = $this->encryptFile();
    }
    $this->file = [
      'filename' => $filename,
      'contents' => $file_contents,
    ];
    unset($this->values->file_path);
  }

  private function cipherSecretForSigners($secret) {
    $signatories = [];
    foreach ($this->values->signers as $signer) {
      $ec = new ECIES();
      $public_key = $signer->e2ee->group->e_client->pub;
      $ec->setPublicKey($public_key);
      $e_pass = $ec->encrypt($secret);
      $signatories[$signer->id] = [
        'e_client' => [
          'e_pass' => $e_pass,
        ],
      ];
    }
    $this->values->signatories = $signatories;
    parent::save();
  }
}
