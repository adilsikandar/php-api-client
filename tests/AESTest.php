<?php
namespace Mifiel\Tests;

use Mifiel\AES;

class AESTest extends \PHPUnit_Framework_TestCase {
  private $defaultAlgorithm = 'AES-192-CBC';

  public function testNewInstanceDefaults() {
    $aes = new AES();
    $this->assertEquals($this->defaultAlgorithm, $aes->algorithm);
  }

  public function testConstructParams() {
    $aes = new AES([
      'algorithm' => 'AES-256-CBC',
    ]);
    $this->assertEquals($aes->algorithm, 'AES-256-CBC');
  }

  public function testSetting() {
    $aes = new AES();
    $aes->algorithm = 'AES-256-CBC';
    $this->assertEquals($aes->algorithm, 'AES-256-CBC');
  }

  public function testRandomIV() {
    $aes = new AES();
    $randomIV = $aes->randomIV();
    $this->assertEquals(strlen($randomIV), 16);

    $randomIV = $aes->randomIV(32);
    $this->assertEquals(strlen($randomIV), 32);

    $randomIV = $aes->randomIV(64);
    $this->assertEquals(strlen($randomIV), 64);
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testRandomIVException() {
    $aes = new AES();
    $aes->randomIV(8);
  }
}
