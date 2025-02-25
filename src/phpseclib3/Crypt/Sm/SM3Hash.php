<?php

namespace phpseclib3\Crypt\Sm;

use phpseclib3\Crypt\Hash;

class SM3Hash extends Hash
{
    private $sm3;

    public function __construct()
    {
        parent::__construct('sm3');
        $this->sm3 = new SM3();
    }

    public function hash($message)
    {
        if ($this->key !== false) {
            // 如果设置了key，使用HMAC
            $blockSize = 64; // SM3的分组长度为512位（64字节）
            $key = strlen($this->key) > $blockSize ?
                $this->sm3->hash($this->key) :
                $this->key;

            $key = str_pad($key, $blockSize, chr(0));
            $ipad = $key ^ str_repeat(chr(0x36), $blockSize);
            $opad = $key ^ str_repeat(chr(0x5c), $blockSize);

            return $this->sm3->hash($opad . pack('H*', $this->sm3->hash($ipad . $message)));
        }

        return $this->sm3->hash($message);
    }

    public function getHash()
    {
        return 'sm3';
    }

    public function getBlockLength()
    {
        return 64; // 512 bits
    }

    public function getLength()
    {
        return 32; // 256 bits
    }
}