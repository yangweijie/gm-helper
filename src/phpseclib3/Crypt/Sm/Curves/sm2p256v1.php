<?php

namespace phpseclib3\Crypt\Sm\Curves;

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class sm2p256v1 extends Prime
{
    protected $hash;
    protected $randomBits;

    public function __construct()
    {
        $modulus = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
        $a = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
        $b = new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
        $baseX = new BigInteger('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16);
        $baseY = new BigInteger('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16);
        $order = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);
        
        $this->setModulo($modulus);
        $this->setCoefficients(
            $a,
            $b
        );
        $this->setBasePoint(
            $baseX,
            $baseY
        );
        $this->setOrder($order);
        $this->setHash('sm3');
    }

    public function setHash($hash)
    {
        $this->hash = $hash;
    }

    public function getHash()
    {
        return $this->hash;
    }

    public function createKey()
    {
        $length = $this->getLength();
        $one = new BigInteger(1);
        $max = $this->getOrder()->subtract($one);

        do {
            $k = BigInteger::randomRange($one, $max);
        } while ($k->equals($one));

        return $k;
    }

    public function getLength()
    {
        if (!isset($this->randomBits)) {
            $this->randomBits = $this->getOrder()->getLength();
        }
        return $this->randomBits;
    }
    public static function getParameters()
    {
        $p = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
        $a = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
        $b = new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
        $x = new BigInteger('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16);
        $y = new BigInteger('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16);
        $n = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);

        return [
            'p' => $p,
            'a' => $a,
            'b' => $b,
            'x' => $x,
            'y' => $y,
            'n' => $n
        ];
    }
}