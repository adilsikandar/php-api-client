<?php
namespace Mifiel\Tests;

use Mifiel\EC;

class ECTest extends \PHPUnit_Framework_TestCase {
  public function testEncryptDecrypt() {
    $ec = new EC();
    $message = 'Bytes stream legend brink flask breed';
    $result = $ec->encrypt('0246d04f5ee3a82a64822141e2c9177774d3fb1754e29af158a941005b6e453ef2', $message);
    $decrypted = $ec->decrypt('3fdbe675ffe10b5d646b3e20a16ec4f44c90374a42d00236f9e2b51ab6cdee16', $result);
    $this->assertEquals($message, $decrypted);
  }

  public function testDecrypt() {
    $ec = new EC();
    $encrypted_data = [
      'iv' => '9b225e38a7b8534a31c5792f504a13a7',
      'ephemPublicKey' => '047cd7ea12facf505add8b319f6da43fa59294eec219ebc99abbc7ac42f32142916f070476f91bc4c8431bebb3d43288f739fc8554fc778291137e918425497b83',
      'ciphertext' => '7547a6868c2e476e9e16351590542b48be9e297a32f63bfd519fb10714ede573',
      'mac' => '06a2108eb960ced35dedd149fd9bad4cb987809341a99544c8311749fbfc60c6',
    ];
    $private_key = '3fdbe675ffe10b5d646b3e20a16ec4f44c90374a42d00236f9e2b51ab6cdee16';
    $decrypted = $ec->decrypt($private_key, join('', $encrypted_data));
    $this->assertEquals($decrypted, 'Mensaje cifrado con ECIES!!! ');

    $encrypted_data = [
      'iv' => '7898733f60c4b0ba8511fb79a2185763',
      'ephemPublicKey' => '04eb63dd5303bcdb5cf9a33491de5c34ed7d845852933954d2d939a7ab5dc9acd6fa28fc952b23de3d7f8ff15f13a14f2513a8ee4031d1691d7a0baab13bf045b2',
      'ciphertext' => 'c91ddd00525a9a67bde3c38015cb096df62193cb57b4a44bb45bf06c86429aae84bca73ff331f6ded983ad59f2341c70',
      'mac' => 'b7e9448a20c6f454f3a4789e3d7ad6de15c60390140374c7ce2d3affe1a49b0e',
    ];
    $private_key = 'c29c6be949cc7a4de005d8236dcce5f17abdc12e64e3f9c4a04e79c5aa6b313b';
    $decrypted = $ec->decrypt($private_key, join('', $encrypted_data));
    $this->assertEquals($decrypted, 'Otro mensaje cifrado con ECIES!!! ');

    $encrypted_data = [
      'iv' => '6b6092a277d024310bc757040d06fcfc',
      'ephemPublicKey' => '04065f0141b69f381244e369c6e88259497568759a2b4531f68cb51faf82ea38e1dfeb63abc7f4175677daca260a26f8e4956524851bf1eb2eef7fc5eee0e6a3c5',
      'ciphertext' => 'dba25ca6bf6250681a27163a638979f379b092d99a47bcaf46af587072ac3306',
      'mac' => '45759db7340288eeb5b0184ef68f76c0138b456d5900ce2de7fdb2d8021505ca',
    ];
    $private_key = 'aefd79cd0e1eb3ba5973596553932246518246283a2c0436882f0b0dc25e25c6';
    $decrypted = $ec->decrypt($private_key, join('', $encrypted_data));
    $this->assertEquals($decrypted, 'Prueba de cifrado con ECIES!!! ');

    $encrypted_data = [
      'iv' => '8b2a2ba78bb5e030849b7e2b4f0657d0',
      'ephemPublicKey' => '0475b57862809b5c8cf15e93c8ccf388e486c50c15a45e933f4f02783540b1559a051412c9971af16572a60d94db244472991a6e3b9c81e8616b61f0ec595c37e6',
      'ciphertext' => 'e9e906851178918df09e1d7e536a93eff0dc613a3f19c9de1de07dd272c5d078eea6e11b4b98dc067113e8ab4329417b',
      'mac' => 'a46be1d4470ade4b9be8abb34889d89d46af5608785c4b3e90b747718a1dd14e',
    ];
    $private_key = '65fae62b6659d952323d7a6b9d937e7ba0c28f77cf5e0f1cc596b0964c69a1d9';
    $decrypted = $ec->decrypt($private_key, join('', $encrypted_data));
    $this->assertEquals($decrypted, 'Prueba de cifrado con ECIES 1234567890');
  }

  /**
   * @expectedException InvalidArgumentException
   */
  public function testInvalidMacException() {
    $ec = new EC();
    $encrypted_data = [
      'iv' => '9b225e38a7b8534a31c5792f504a13a7',
      'ephemPublicKey' => '047cd7ea12facf505add8b319f6da43fa59294eec219ebc99abbc7ac42f32142916f070476f91bc4c8431bebb3d43288f739fc8554fc778291137e918425497b83',
      'ciphertext' => '7547a6868c2e476e9e16351590542b48be9e297a32f63bfd519fb10714ede573',
      'mac' => '06a2108eb960ced35dedd149fd9bad4cb987809341a99544c8311749fbfc60c5',
    ];
    $private_key = '3fdbe675ffe10b5d646b3e20a16ec4f44c90374a42d00236f9e2b51ab6cdee16';
    $decrypted = $ec->decrypt($private_key, join('', $encrypted_data));
    $this->assertEquals($decrypted, 'Mensaje cifrado con ECIES!!! ');
  }
}
