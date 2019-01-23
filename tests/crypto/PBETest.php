<?php
namespace Mifiel\Tests;

use Mifiel\Crypto\PBE;

class PBETest extends \PHPUnit_Framework_TestCase {
  private $defaultNumIterations = 1000;
  private $defaultDigestAlgorithm = 'sha256';

  public function testNewInstanceDefaults() {
    $pbe = new PBE();
    $this->assertEquals($this->defaultNumIterations, $pbe->getIterations());
    $this->assertEquals($this->defaultDigestAlgorithm, $pbe->getDigestAlgorithm());
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testNewInstanceException() {
    $pbe = new PBE(1200);
  }

  public function testConstructParams() {
    $params = [
      'iterations' => 2000,
      'digestAlgorithm' => 'md5',
    ];
    $pbe = new PBE($params);
    $this->assertEquals($params['iterations'], $pbe->getIterations());
    $this->assertEquals($params['digestAlgorithm'], $pbe->getDigestAlgorithm());
  }

  public function testSetting() {
    $pbe = new PBE();
    $pbe->setIterations(2000);
    $this->assertEquals(2000, $pbe->getIterations());
    $pbe->setDigestAlgorithm('md5');
    $this->assertEquals('md5', $pbe->getDigestAlgorithm());
  }

  public function testRandomPassword() {
    $pbe = new PBE();
    $passwordA = $pbe->randomPassword();
    $passwordB = PBE::randomPassword(18);
    $passwordC = $pbe->randomPassword(120);
    $this->assertEquals(strlen($passwordA), 32);
    $this->assertEquals(strlen($passwordB), 18);
    $this->assertEquals(strlen($passwordC), 120);
  }

  public function testRandomSalt() {
    $pbe = new PBE();
    $this->assertEquals(strlen(PBE::randomSalt()), 16);
    $this->assertEquals(strlen(PBE::randomSalt(32)), 32);
    $this->assertEquals(strlen(PBE::randomSalt(64)), 64);
  }

  public function testGetDerivedKey() {
    $pbe = new PBE();
    $pbe->setIterations(1);
    $derivedKey = $pbe->getDerivedKey([
      'password' => 'passwd',
      'salt' => 'salt',
      'size' => 64,
    ]);
    $this->assertEquals($derivedKey, '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783');
    $derivedKey = $pbe->getDerivedKey([
      'password' => 'password',
      'salt' => 'salt',
      'size' => 32,
    ]);
    $this->assertEquals($derivedKey, '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');

    $pbe->setIterations(80000);
    $derivedKey = $pbe->getDerivedKey([
      'password' => 'Password',
      'salt' => 'NaCl',
      'size' => 64,
    ]);
    $this->assertEquals($derivedKey, '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d');

    $pbe->setIterations(2);
    $derivedKey = $pbe->getDerivedKey([
      'password' => 'password',
      'salt' => 'salt',
      'size' => 32,
    ]);
    $this->assertEquals($derivedKey, 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43');

    $pbe->setIterations(4096);
    $derivedKey = $pbe->getDerivedKey([
      'password' => 'password',
      'salt' => 'salt',
      'size' => 32,
    ]);
    $this->assertEquals($derivedKey, 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
    $derivedKey = $pbe->getDerivedKey([
      'password' => 'passwordPASSWORDpassword',
      'salt' => 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
      'size' => 40,
    ]);
    $this->assertEquals($derivedKey, '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9');

    $pbe->setIterations(1024);
    $derivedKey = $pbe->getDerivedKey([
      'password' => '',
      'salt' => 'salt',
      'size' => 32,
    ]);
    $this->assertEquals($derivedKey, '9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d');
    $derivedKey = $pbe->getDerivedKey([
      'password' => 'password',
      'salt' => '',
      'size' => 32,
    ]);
    $this->assertEquals($derivedKey, 'ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46');
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testDerivedKeyException() {
    $pbe = new PBE();
    $pbe->getDerivedKey([
      'password' => 'password',
      'salt' => 'salt',
      'size' => 1001,
    ]);
  }
}
