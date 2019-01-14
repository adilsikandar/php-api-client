<?php
namespace Mifiel\Tests;

use Mifiel\EC;

class ECTest extends \PHPUnit_Framework_TestCase {
  public function testNewInstanceDefaults() {
    // $ec = new EC();
    EC::encrypt();
    // $this->assertEquals('bla', $ec->bla);
  }
}
