<?php
namespace Mifiel;

use GuzzleHttp\Psr7\Request,
    Acquia\Hmac\Guzzle\HmacAuthMiddleware,
    GuzzleHttp\Client,
    GuzzleHttp\HandlerStack,
    Acquia\Hmac\RequestSigner,
    BitWasp\Buffertools\Buffer as BitWaspBuffer,
    BitWasp\Bitcoin\Key\Deterministic\HierarchicalKeyFactory,
    Mifiel\Digest\ApiAuthGemDigest;

class ApiClient {

  private static $appId;
  private static $appSecret;
  private static $client;
  private static $url;
  private static $masterKey;

  public static function setTokens($appId, $appSecret, $masterKey=null) {
    self::$appId = $appId;
    self::$appSecret = $appSecret;
    self::$url = 'https://www.mifiel.com/api/v1/';
    self::setClient();
    if ($masterKey) {
      self::setMasterKey($masterKey);
    }
  }

  public static function setMasterKey($seed) {
    $seed = new BitWaspBuffer(hex2bin($seed));
    self::$masterKey = HierarchicalKeyFactory::fromEntropy($seed);
  }

  public static function get($path, $params=array()) {
    return self::request('GET', $path, $params);
  }

  public static function post($path, $params=array(), $multipart=false) {
    return self::request('POST', $path, $params, $multipart);
  }

  public static function delete($path) {
    return self::request('DELETE', $path);
  }

  public static function put($path, $params=array(), $multipart=false) {
    return self::request('PUT', $path, $params, $multipart);
  }

  private static function request($type, $path, $params=array(), $multipart=false) {
    $options = [];
    if ($multipart) {
      $options['multipart'] = self::build_multipart($params);
    } elseif(!empty($params)) {
      $options['json'] = $params;
    }
    // $options['headers'] = [
    //   'content-md5' => base64_encode(md5(json_encode($params), true))
    // ];
    return self::$client->request(strtoupper($type), $path, $options);
  }

  private static function build_multipart($params) {
    $multipart_arr = array();
    foreach ($params as $name => $value) {
      $field = self::build_field($name, $value);
      if ($field){
        array_push($multipart_arr, $field);
      }
    }
    return $multipart_arr;
  }

  private static function build_field($name, $value) {
    if (is_array($value) && isset($value['filename'])) {
      return [
        'name'      => $name,
        'contents'  => $value['contents'],
        'filename'  => $value['filename']
      ];
    }
    if (!empty($value) && gettype($value) != 'NULL') {
      if (is_bool($value)){
        $value = $value === true ? '1' : '0';
      } elseif (is_array($value) || is_object($value)) {
        $value = json_encode($value);
      }

      return [
        'name' => $name,
        'contents' => $value
      ];
    }
    return false;
  }

  public static function url($url=null){
    if ($url){
      self::$url = $url;
      self::setClient();
    } else {
      return self::$url;
    }
  }

  public static function appId($appId=null) {
    if ($appId) {
      self::$appId = $appId;
      self::setClient();
      return;
    }
    return self::$appId;
  }

  public static function appSecret($appSecret=null) {
    if ($appSecret) {
      self::$appSecret = $appSecret;
      self::setClient();
      return;
    }
    return self::$appSecret;
  }

  public static function masterKey() {
    return self::$masterKey;
  }

  private static function setClient() {
    $signer = new RequestSigner(new ApiAuthGemDigest());
    $signer->setProvider('APIAuth');

    $middleware = new HmacAuthMiddleware(
      $signer,
      self::$appId,
      self::$appSecret
    );

    $stack = HandlerStack::create();
    $stack->push($middleware);

    self::$client = new Client([
      'base_uri' => self::url(),
      'handler' => $stack,
    ]);
  }

  public static function getClient() {
    return self::$client;
  }
}
