<?php

namespace Signer\Manager\Client\Interceptor;

use \Monolog\Logger;
use \Monolog\Formatter\LineFormatter;
use \Monolog\Handler\StreamHandler;

use \Signer\Manager\Client\Interceptor\MyLogger;

use \Signer\Manager\Client\ApiException;

Class KeyHandler{
    private $private_key = null;
    private $public_key = null;
    private $logger = null;
    public function __construct($keypair_route = null, $cdc_cert_route = null, $password = ""){

        if($keypair_route == null || empty($keypair_route)){
            throw new ApiException(" ::::Could not verify the Keypair route:::: ", 404,[],"");
        }
        else if($cdc_cert_route == null || empty($cdc_cert_route)){
           throw new ApiException(" ::::Could not verify the cert route:::: ", 404,[],"");
        }
        else{
            $this->logger = new MyLogger('KeyHandler');
        
            $keypair_file = $keypair_route;
            $cert_file = $cdc_cert_route;

            if(!file_exists($keypair_file)){
                throw new ApiException(" ::::Could not verify the keypair file:::: ", 404,[],""); 
            }
            elseif (!file_exists($cert_file)) {
                throw new ApiException(" ::::Could not verify the cert file:::: ", 404,[],"");
            }
            else{
                $this->logger->info("Keypair file is: ".$keypair_file);
                $this->logger->info("CDC certificate is: ".$cert_file);

                $pkcs12 = array();
                try{
                    $file_pkcs12 = file_get_contents($keypair_file);
                    if (isset($file_pkcs12)) {
                        $valkeypair = openssl_pkcs12_read($file_pkcs12, $pkcs12, $password);
                        if (!$valkeypair) {
                            throw new ApiException(" :::The content of the keypair file is not valid:::: ", 400,[],"");
                        }
                        else{
                            if (isset($pkcs12['pkey'])) {
                                $this->logger->info("Private key loaded");
                                $this->private_key = openssl_pkey_get_private($pkcs12['pkey']);
                            }
                            else{
                                throw new ApiException(" :::Could not read private key, please review your configuration:::: ", 404,[],"");
                            }
                        }
                    }
                    else{
                        throw new ApiException(" :::Could not read pkcs12 file, please review your configuration:::: ", 404,[],"");
                    }
                    $file_cert = file_get_contents($cert_file);
                    if (isset($file_cert)) {
                        $this->public_key = openssl_pkey_get_public($file_cert);
                        if(!$this->public_key){
                            throw new ApiException(" :::The content of the cert file is not valid:::: ", 400,[],"");
                        }
                        else{
                            $this->logger->info("Public key loaded");
                            $this->public_key = openssl_pkey_get_public($file_cert);
                        }
                    }
                    else{
                        throw new ApiException(" :::Could not read public key, please review your configuration:::: ", 404,[],"");
                    }
                }
                catch(Exception $e){
                    $this->logger->error('Exception at __construct: '.$e->getMessage().PHP_EOL);
                }
            }
        }
    }

    public function getSignatureFromPrivateKey($toSign){
        $signature_text = null;
        try{
            if ($toSign == null || empty($toSign)) {
                throw new ApiException(" :::The payload is empty::: ", 400,[],"");
            }
            else if ($this->private_key == null || empty($this->private_key)) {
                throw new ApiException(" :::The privatekey is empty::: ", 400,[],"");
            }
            else{
                openssl_sign($toSign, $signature, $this->private_key, OPENSSL_ALGO_SHA256);
                $signature_text = bin2hex($signature);

                if (isset($signature_text)) {
                    $this->logger->info("The signature is: ".$signature_text);
                }
            }
        }
        catch(Exception $e){
            throw new ApiException(" :::Exception when calling getSignatureFromPrivateKey::: ", 500,[],"");
        }
        
        return $signature_text;
    }

    public function getVerificationFromPublicKey($data, $signature){
        $is_verified = false;
        if($data == null || empty($data)){
            throw new ApiException(" :::The data is empty::: ", 404,[],"");
        }
        elseif ($signature == null || empty($signature)) {
            throw new ApiException(" :::The signature is empty::: ", 404,[],"");
        }
        else{
            try{
                $signature = hex2bin($signature);
                if(!$signature){
                    throw new ApiException(" :::The signature is failed::: ", 404,[],"");
                }
                else{
                    if (!isset($signature)) {
                        throw new ApiException(" :::Signature not given or is malformed::: ", 404,[],"");
                    }
                    else if ($this->public_key == null || empty($this->public_key)) {
                        throw new ApiException(" :::Could not read public key, please review your configuration::: ", 404,[],"");
                    }
                    else{
                        $result = openssl_verify($data, $signature, $this->public_key, OPENSSL_ALGO_SHA256);
                        $result == 1 ? $is_verified = true : $is_verified = false;
                    }
                }

            }catch (Exception $e){
                throw new ApiException(" :::Exception when calling getVerificationFromPublicKey::: ", 500,[],"");
            }
        }
        return $is_verified;
    }
    
    public function close(){
        return openssl_free_key($this->private_key) && openssl_free_key($this->public_key);
    }
}
?>