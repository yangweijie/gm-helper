<?php

namespace phpseclib3\Crypt\Sm;

use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\PrivateKey;
use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Exception\UnsupportedOperationException;
use phpseclib3\Math\BigInteger;

class SM2 extends EC
{
    protected $curve = 'sm2p256v1';
    protected $hash = 'sm3';
    protected $privateKey;
    protected $publicKey;

    protected static $plugins;

    public static function initialize_static_variables()
    {
        parent::initialize_static_variables();
        self::$plugins = [
            'Signature' => [
                'Raw' => 'phpseclib3\\Crypt\\SM\\Formats\\Signature\\Raw',
                'ASN1' => 'phpseclib3\\Crypt\\SM\\Formats\\Signature\\ASN1'
            ],
            'Keys' => [
                'PKCS1' => 'phpseclib3\\Crypt\\SM\\Formats\\Keys\\PKCS1',
                'PKCS8' => 'phpseclib3\\Crypt\\SM\\Formats\\Keys\\PKCS8'
            ]
        ];
    }

    public function __construct()
    {
        self::initialize_static_variables();
        
        // 创建曲线实例
        $curveClass = 'phpseclib3\\Crypt\\Sm\\Curves\\' . $this->curve;
        $curve = new $curveClass();
        
        parent::__construct();
        $this->curve = $curve;
        $this->hash = 'sm3';
        $this->format = 'raw';
        $this->shortFormat = 'raw';
        $this->sigFormat = 'raw';
    }

    public static function encryptWithKey($message, $publicKey)
    {
        $instance = new self();
        $instance->loadKey(['publicKey' => $publicKey]);
        return $instance->encrypt($message);
    }

    public static function decryptWithKey($ciphertext, $privateKey)
    {
        $instance = new self();
        $instance->loadKey(['privateKey' => $privateKey]);
        return $instance->decrypt($ciphertext);
    }

    public static function signWithKey($message, $privateKey)
    {
        $instance = new self();
        $instance->loadKey(['privateKey' => $privateKey]);
        return $instance->sign($message);
    }

    public static function verifyWithKey($message, $signature, $publicKey)
    {
        $instance = new self();
        $instance->loadKey(['publicKey' => $publicKey]);
        return $instance->verify($message, $signature);
    }

    protected function encryptMessage($message, $publicKey)
    {
        // 实现加密逻辑
        return '';
    }

    protected function decryptMessage($ciphertext, $privateKey)
    {
        // 实现解密逻辑
        return '';
    }

    protected function signMessage($message, $privateKey)
    {
        // 实现签名逻辑
        return '';
    }

    protected function verifySignature($message, $signature, $publicKey)
    {
        // 实现验证逻辑
        return true;
    }

     /**
     * Create public / private key pair.
     *
     * @param string $curve
     * @return PrivateKey
     */
    public static function createKey($curve = 'sm2p256v1')
    {
        self::initialize_static_variables();

        if (!isset(self::$engines['PHP'])) {
            self::useBestEngine();
        }

        $class = new \ReflectionClass(static::class);
        if ($class->isFinal()) {
            throw new \RuntimeException('createKey() should not be called from final classes (' . static::class . ')');
        }

        $curve = strtolower($curve);
        $curveClass = '\phpseclib3\Crypt\Sm\Curves\\' .$curve;

        if (!class_exists($curveClass)) {
            throw new UnsupportedCurveException('Named Curve of ' . $curve . ' is not supported');
        }

        $curveObject = new $curveClass();
        $key = new static();
        $key->curve = $curveObject;
        $key->privateKey = $curveObject->createKey();
        $key->hash = 'sm3';

        $publicKey = $key->getPublicKey();
        return [
            'privateKey' => $key->privateKey->toHex(),
            'publicKey' => bin2hex($publicKey->publicKey)
        ];
    }

    public function loadKey($key)
    {
        if (is_array($key)) {
            if (isset($key['privateKey'])) {
                $this->privateKey = new BigInteger($key['privateKey'], 16);
                $this->publicKey = null; // 清除公钥
                return true;
            } elseif (isset($key['publicKey'])) {
                $pubKey = $key['publicKey'];
                if (strlen($pubKey) == 128) {
                    $pubKey = '04' . $pubKey;
                }
                $this->publicKey = hex2bin($pubKey);
                $this->privateKey = null; // 清除私钥
                return true;
            }
        } else if (ctype_xdigit($key)) {
            $keyLength = strlen($key);
            if ($keyLength == 64) { // 私钥
                $this->privateKey = new BigInteger($key, 16);
                $this->publicKey = null; // 清除公钥
                return true;
            } else if ($keyLength == 128 || $keyLength == 130) { // 公钥（带或不带04前缀）
                if ($keyLength == 128) {
                    $key = '04' . $key;
                }
                $this->publicKey = hex2bin($key);
                $this->privateKey = null; // 清除私钥
                return true;
            }
        }
        throw new UnsupportedOperationException('无效的密钥格式');
    }

    public function encrypt($message)
    {
        if (empty($message)) {
            return '';
        }
        if (!$this->publicKey) {
            throw new UnsupportedOperationException('未设置公钥');
        }
        $k = $this->curve->createKey();
        $point = $this->curve->multiplyPoint($this->curve->getBasePoint(), $k);
        $pubPoint = [
            $this->curve->convertInteger(new BigInteger(bin2hex(substr($this->publicKey, 1, 32)), 16)),
            $this->curve->convertInteger(new BigInteger(bin2hex(substr($this->publicKey, 33, 32)), 16))
        ];
        $x2y2 = $this->curve->multiplyPoint($pubPoint, $k);
        $c1 = bin2hex($point[0]->toBytes() . $point[1]->toBytes());
        $klen = strlen($message);
        $ct = '';
        $offset = 0;
        while ($offset < $klen) {
            $ct .= hex2bin(SM3::hash($x2y2[0]->toBytes() . pack('N', $offset / 32)));
            $offset += 32;
        }
        $ct = substr($ct, 0, $klen);
        $c2 = bin2hex($message ^ $ct);
        $c3 = bin2hex(hex2bin(SM3::hash($x2y2[0]->toBytes() . $message . $x2y2[1]->toBytes())));
        return $c1 . $c2 . $c3;
    }

    public function decrypt($ciphertext)
    {
        if (empty($ciphertext)) {
            return '';
        }
        if (!$this->privateKey) {
            throw new UnsupportedOperationException('未设置私钥');
        }
        $c1 = substr($ciphertext, 0, 128);
        $c2 = substr($ciphertext, 128, -64);
        $c3 = substr($ciphertext, -64);
        $point = [
            $this->curve->convertInteger(new BigInteger(substr($c1, 0, 64), 16)),
            $this->curve->convertInteger(new BigInteger(substr($c1, 64, 64), 16))
        ];
        $x2y2 = $this->curve->multiplyPoint($point, $this->privateKey);
        $klen = strlen(hex2bin($c2));
        $ct = '';
        $offset = 0;
        while ($offset < $klen) {
            $ct .= hex2bin(SM3::hash($x2y2[0]->toBytes() . pack('N', $offset / 32)));
            $offset += 32;
        }
        $ct = substr($ct, 0, $klen);
        $message = hex2bin($c2) ^ $ct;
        if ($c3 !== SM3::hash($x2y2[0]->toBytes() . $message . $x2y2[1]->toBytes())) {
            throw new UnsupportedOperationException('解密验证失败');
        }
        return $message;
    }

    public function sign($message)
    {
        if (!$this->privateKey) {
            throw new UnsupportedOperationException('未设置私钥');
        }
        if (empty($message)) {
            return '';
        }
        $e = new BigInteger(bin2hex(hex2bin(SM3::hash($message))), 16);
        do {
            $k = $this->curve->createKey();
            $point = $this->curve->multiplyPoint($this->curve->getBasePoint(), $k);
            $r = $e->add(new BigInteger(bin2hex($point[0]->toBytes()), 16))->modPow(new BigInteger('1'), $this->curve->getOrder());
            if ($r->equals(new BigInteger('0')) || $r->add($k)->equals($this->curve->getOrder())) {
                continue;
            }
            $s = $this->privateKey->add(new BigInteger('1'))->modInverse($this->curve->getOrder())->multiply(
                $k->subtract($r->multiply($this->privateKey))
            )->modPow(new BigInteger('1'), $this->curve->getOrder());
        } while ($s->equals(new BigInteger('0')));
        return bin2hex($r->toBytes() . $s->toBytes());
    }

    public function verify($message, $signature)
    {
        if (!$this->publicKey) {
            throw new UnsupportedOperationException('未设置公钥');
        }
        if (empty($message) && empty($signature)) {
            return true;
        }
        $signature = hex2bin($signature);
        $r = new BigInteger(bin2hex(substr($signature, 0, 32)), 16);
        $s = new BigInteger(bin2hex(substr($signature, 32, 32)), 16);
        if ($r->equals(new BigInteger('0')) || $r->compare($this->curve->getOrder()) >= 0 ||
            $s->equals(new BigInteger('0')) || $s->compare($this->curve->getOrder()) >= 0) {
            return false;
        }
        $e = new BigInteger(bin2hex(hex2bin(SM3::hash($message))), 16);
        $t = $r->add($s)->modPow(new BigInteger('1'), $this->curve->getOrder());
        if ($t->equals(new BigInteger('0'))) {
            return false;
        }
        $pubPoint = [
            $this->curve->convertInteger(new BigInteger(bin2hex(substr($this->publicKey, 1, 32)), 16)),
            $this->curve->convertInteger(new BigInteger(bin2hex(substr($this->publicKey, 33, 32)), 16))
        ];
        $point1 = $this->curve->multiplyPoint($this->curve->getBasePoint(), $s);
        $point2 = $this->curve->multiplyPoint($pubPoint, $t);
        $point = $this->curve->addPoint($point1, $point2);
        $R = $e->add(new BigInteger(bin2hex($point[0]->toBytes()), 16))->modPow(new BigInteger('1'), $this->curve->getOrder());
        return $r->equals($R);
    }

    public function toString($type, array $options = [])
    {
        if ($type === 'raw') {
            if ($this->privateKey) {
                return bin2hex($this->privateKey);
            } else if ($this->publicKey) {
                return bin2hex($this->publicKey);
            }
            return '';
        }
        return sprintf('SM2 Key\nCurve: %s\nHash: %s', $this->curve, $this->hash);
    }

    public function getPublicKey()
    {
        $publicKey = new static();
        $publicKey->curve = $this->curve;
        $publicKey->hash = $this->hash;
        $point = $this->curve->multiplyPoint($this->curve->getBasePoint(), $this->privateKey);
        $publicKey->publicKey = "\x04" . $point[0]->toBytes() . $point[1]->toBytes();
        return $publicKey;
    }
}