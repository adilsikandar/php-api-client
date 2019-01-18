<?php
namespace Mifiel\Tests;

use Mifiel\Crypto\AES;

class AESTest extends \PHPUnit_Framework_TestCase {
  private $defaultBlockSize = 192;
  private $defaultAlgorithm = 'AES-192-CBC';

  public function testNewInstanceDefaults() {
    $aes = new AES();
    $this->assertEquals($this->defaultAlgorithm, $aes->getAlgorithm());
  }

  public function testConstructParams() {
    $aes = new AES([
      'blockSize' => 256,
    ]);
    $this->assertEquals(256, $aes->getBlockSize());
    $this->assertEquals('AES-256-CBC', $aes->getAlgorithm());
  }

  public function testSetting() {
    $aes = new AES();
    $aes->setBlockSize(256);
    $this->assertEquals('AES-256-CBC', $aes->getAlgorithm());
  }

  public function testRandomIV() {
    $aes = new AES();
    $randomIV = $aes->randomIV();
    $this->assertEquals(16, strlen($randomIV));

    $randomIV = AES::randomIV(32);
    $this->assertEquals(32, strlen($randomIV));

    $randomIV = $aes->randomIV(64);
    $this->assertEquals(64, strlen($randomIV));
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testRandomIVException() {
    $aes = new AES();
    $aes->randomIV(8);
  }

  public function testEncrypt() {
    $aes = new AES();
    $aes->setBlockSize(128);
    $result = $aes->encrypt('cifrado de Prueba', '1234567890123456', '69762074657374696976207465737469');
    $this->assertEquals('2a53e7c3cb4eb67dc91a175f27c92c884bc5965b767a4e68fda99efa80b08451', $result['encrypted_data']);

    $result = $aes->encrypt('test de cifrado', 'derivedKEY234556', '34363538373838373734343536353231');
    $this->assertEquals('d1e57e056b9a7b4d4b8526d0c2298672', $result['encrypted_data']);

    $result = $aes->encrypt('test de cifrado', 'a9r82*9rn5Flp3/o', '35383738386164663536353436353436');
    $this->assertEquals('aaa6d00253557f184f8b5ff9ea3ccec2', $result['encrypted_data']);

    $aes->setBlockSize(192);
    $result = $aes->encrypt('cifrado de Prueba AES-192', '123456789012345678901234', '64667364383734353334356654353938');
    $this->assertEquals('e363fed7986813992fa4251831f520abf2db23dc810df71824f2bae3d70245c1', $result['encrypted_data']);

    $result = $aes->encrypt('test de cifrado AES-192', 'derivedKEY234556iksRtryr', '72667364383734353536356654353938');
    $this->assertEquals('0d30f571d5fafc8fd78701a508f8234f8d2b55c4ec233fce70a40ada7f378041', $result['encrypted_data']);

    $result = $aes->encrypt('encrypted decrypted data', '*854FrGTH/hgf_4f6h9v4dfg', '2e397464383734353536356654353938');
    $this->assertEquals('c40f20cfa7706678f7be40b0f52f8ae2b796a91021a7ad9c826dd6f666845261', $result['encrypted_data']);

    $aes->setBlockSize(256);
    $result = $aes->encrypt('cifrado de Prueba AES-256', '12345678901234567890123456789012', '39382e2e2d6438373435353635665435');
    $this->assertEquals('ebf268a7547877027ef2bc954244bac5cd3d70f6126b0fe0c3d0c15f3219b432', $result['encrypted_data']);

    $result = $aes->encrypt('test de cifrado AES-256', 'derivedKEY234556iksRtryrtg578hfr', '72667364383734353536356654353938');
    $this->assertEquals('16a71cf1efa9e29e15022b5c9467fb60230420bb15ba1fbfd258418b85c077e5', $result['encrypted_data']);

    $result = $aes->encrypt('test de cifrado', '*854FrGTH/hgf_4f6h9v4dfg*&jr-jew', '2e397464383734353536356654353938');
    $this->assertEquals('66280287288a9f10d55f3b1c6c10bc94', $result['encrypted_data']);
  }

  public function testDecrypt() {
    $aes = new AES();
    $aes->setBlockSize(128);
    $decryptedData = $aes->decrypt('2a53e7c3cb4eb67dc91a175f27c92c884bc5965b767a4e68fda99efa80b08451', '1234567890123456', '69762074657374696976207465737469');
    $this->assertEquals('cifrado de Prueba', $decryptedData);

    $decryptedData = $aes->decrypt('d1e57e056b9a7b4d4b8526d0c2298672', 'derivedKEY234556', '34363538373838373734343536353231');
    $this->assertEquals('test de cifrado', $decryptedData);

    $decryptedData = $aes->decrypt('aaa6d00253557f184f8b5ff9ea3ccec2', 'a9r82*9rn5Flp3/o', '35383738386164663536353436353436');
    $this->assertEquals('test de cifrado', $decryptedData);

    $aes->setBlockSize(192);
    $decryptedData = $aes->decrypt('e363fed7986813992fa4251831f520abf2db23dc810df71824f2bae3d70245c1', '123456789012345678901234', '64667364383734353334356654353938');
    $this->assertEquals('cifrado de Prueba AES-192', $decryptedData);

    $decryptedData = $aes->decrypt('0d30f571d5fafc8fd78701a508f8234f8d2b55c4ec233fce70a40ada7f378041', 'derivedKEY234556iksRtryr', '72667364383734353536356654353938');
    $this->assertEquals('test de cifrado AES-192', $decryptedData);

    $decryptedData = $aes->decrypt('c40f20cfa7706678f7be40b0f52f8ae2b796a91021a7ad9c826dd6f666845261', '*854FrGTH/hgf_4f6h9v4dfg', '2e397464383734353536356654353938');
    $this->assertEquals('encrypted decrypted data', $decryptedData);

    $aes->setBlockSize(256);
    $decryptedData = $aes->decrypt('ebf268a7547877027ef2bc954244bac5cd3d70f6126b0fe0c3d0c15f3219b432', '12345678901234567890123456789012', '39382e2e2d6438373435353635665435');
    $this->assertEquals('cifrado de Prueba AES-256', $decryptedData);

    $decryptedData = $aes->decrypt('16a71cf1efa9e29e15022b5c9467fb60230420bb15ba1fbfd258418b85c077e5', 'derivedKEY234556iksRtryrtg578hfr', '72667364383734353536356654353938');
    $this->assertEquals('test de cifrado AES-256', $decryptedData);

    $decryptedData = $aes->decrypt('66280287288a9f10d55f3b1c6c10bc94', '*854FrGTH/hgf_4f6h9v4dfg*&jr-jew', '2e397464383734353536356654353938');
    $this->assertEquals('test de cifrado', $decryptedData);
  }
}
