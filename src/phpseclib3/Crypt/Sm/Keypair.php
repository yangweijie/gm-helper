<?php

namespace phpseclib3\Crypt\Sm;

class Keypair
{
    private $privateKey;
    private $publicKey;

    public function __construct($privateKey = null, $publicKey = null)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    public static function generate()
    {
        $sm2 = new SM2();
        $keys = $sm2->createKey();
        return new self($keys['privateKey'], $keys['publicKey']);
    }

    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    public function setPublicKey($publicKey)
    {
        $this->publicKey = $publicKey;
        return $this;
    }
}