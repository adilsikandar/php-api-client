<?php
namespace Mifiel\Tests;

use Mifiel\ApiClient,
    Mifiel\Document,
    BitWasp\Buffertools\Buffer as BitWaspBuffer,
    BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory,
    Mockery as m;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class DocumentTest extends \PHPUnit_Framework_TestCase {

  /**
   * @after
   **/
  public function allowMockeryAsertions() {
    if ($container = m::getContainer()) {
      $this->addToAssertionCount($container->mockery_getExpectationCount());
    }
  }

  public function testCreate() {
    $document = new Document([
      'file_path' => './tests/fixtures/FIEL_AAA010101AAA.cer'
    ]);

    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('post')
      ->with('documents', m::type('Array'), true)
      ->andReturn(new \GuzzleHttp\Psr7\Response)
      ->once();

    $document->save();
  }

  public function testSaveFile() {
    $document = new Document(['id' => 'some-id']);
    $path = 'tmp/the-file.pdf';
    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('get')
      ->with('documents/some-id/file')
      ->andReturn(new \GuzzleHttp\Psr7\Response)
      ->once();

    $document->saveFile($path);
  }

  public function testSaveFileSigned() {
    $document = new Document(['id' => 'some-id']);
    $path = 'tmp/the-file-signed.pdf';
    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('get')
      ->with('documents/some-id/file_signed')
      ->andReturn(new \GuzzleHttp\Psr7\Response)
      ->once();
    $document->saveFileSigned($path);
  }

  public function testSaveXml() {
    $document = new Document(['id' => 'some-id']);
    $path = 'tmp/the-file.xml';
    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('get')
      ->with('documents/some-id/xml')
      ->andReturn(new \GuzzleHttp\Psr7\Response)
      ->once();
    $document->saveXML($path);
  }

  public function testUpdate() {
    $document = new Document();
    $document->id = 'some-id';

    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('put')
      ->with('documents/some-id', array('id' => 'some-id'), true)
      ->andReturn(new \GuzzleHttp\Psr7\Response)
      ->once();

    $document->save();
  }

  public function testAll() {
    $mockResponse = m::mock('\GuzzleHttp\Psr7\Response');
    $mockResponse->shouldReceive('getBody')
                 ->once()
                 ->andReturn('[{"id": "some-id"}]');
    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('get')
      ->with('documents')
      ->andReturn($mockResponse)
      ->once();

    $documents = Document::all();
  }

  public function testFind() {
    $mockResponse = m::mock('\GuzzleHttp\Psr7\Response');
    $mockResponse->shouldReceive('getBody')
                 ->once()
                 ->andReturn('{"id": "some-id"}');
    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('get')
      ->with('documents/some-id')
      ->andReturn($mockResponse)
      ->once();

    Document::find('some-id');
  }

  public function testSetGetProperties() {
    $original_hash = hash('sha256', 'some-document-contents');
    $document = new Document([
      'original_hash' => $original_hash
    ]);
    $this->assertEquals($original_hash, $document->original_hash);

    $new_original_hash = 'blah';
    $document->original_hash = $new_original_hash;
    $this->assertEquals($new_original_hash, $document->original_hash);
  }

  public function testDelete() {
    m::mock('alias:Mifiel\ApiClient')
      ->shouldReceive('delete')
      ->with('documents/some-id')
      ->andReturn(new \GuzzleHttp\Psr7\Response)
      ->once();

    Document::delete('some-id');
  }

  public function testCreateEncrypted() {
    $mockedBody = '{"id": "some-id", "signers":';
    $mockedBody .= '[{ "id": "0ac0c4f7-d3e6-40c1-a079-a0e58db645e6", "e2ee": { "group": { "e_client": { "pub": "0246d04f5ee3a82a64822141e2c9177774d3fb1754e29af158a941005b6e453ef2" } } } },';
    $mockedBody .= '{ "id": "ff946596-c4c4-4b89-9990-b50ef6ef7d07", "e2ee": { "group": { "e_client": { "pub": "034c81835ab30eb33aa248cc7712315d7dcaf4c870e09a4c9a840db516d391cead" } } } } ] }';

    $mockResponse = m::mock('\GuzzleHttp\Psr7\Response');
    $mockResponse->shouldReceive('getBody')
                 ->once()
                 ->andReturn($mockedBody);

    $document = new Document([
      'encrypted' => true,
      'file_path' => './tests/fixtures/example.pdf',
    ]);

    $seed = new BitWaspBuffer(hex2bin('000102030405060708090a0b0c0d0e0f'));
    $mockMasterKey = HierarchicalKeyFactory::fromEntropy($seed);

    $mock = m::mock('alias:Mifiel\ApiClient');
    $mock->shouldReceive([
      'post' => $mockResponse,
      'put' => new \GuzzleHttp\Psr7\Response,
      'masterKey' => $mockMasterKey,
    ]);

    $document->save();
  }
}
