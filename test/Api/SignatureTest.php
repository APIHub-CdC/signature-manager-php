<?php

namespace Signer\Manager;

use \GuzzleHttp\Client;
use \GuzzleHttp\Event\Emitter;
use \GuzzleHttp\Middleware;
use \GuzzleHttp\HandlerStack as handlerStack;

use \Signer\Manager\ApiException;
use \Signer\Manager\Interceptor\KeyHandler;
use \Signer\Manager\Interceptor\MiddlewareEvents;

class SignatureTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->cadena = 'XXXXXXX';
        $this->signature = null;
        $this->signer = null;
        $this->valida = null;
        $this->keypair = '/path/to/keypair.p12';
        $this->cert = '/path/to/certificate.pem';
        $this->password = getenv('KEY_PASSWORD');
    }
    
    public function testKeyPairCert(){
        try{

            $this->signer = new KeyHandler($this->keypair, $this->cert, $this->password);
            $result = $this->signer;
            $this->assertTrue($this->signer == true);
            return $result;
        }
        catch(ApiException $e){
            echo ' code. Exception ::: '.$e->getCode(). ' ' .$e->getMessage();
        }
        
    }
    
    /**
     * @depends testKeyPairCert
     */
    public function testSignatureFromPrivatekey($signer)
    {
        try{
            $this->signature = $signer;
            $result = $this->signature->getSignatureFromPrivateKey($this->cadena);
            $this->assertTrue($result != null);
            return $result;
        }
        catch(ApiException $e){
            echo ' code. Exception ::: '.$e->getCode(). ' ' .$e->getMessage();
        }
        
    }

    /**
     * @depends testKeyPairCert
     * @depends testSignatureFromPrivatekey
     */
    public function testVerificationFromPublicKey($signer,$signature){
        try{
            $this->signer = $signer;
            $this->valida = $this->signer->getVerificationFromPublicKey($this->cadena,$signature);
            $this->assertTrue($this->valida == true);
        }
        catch(ApiException $e){
            echo ' code. Exception ::: '.$e->getCode(). ' ' .$e->getMessage();
        }
    }
    
}
