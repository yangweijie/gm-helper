<?php

namespace phpseclib3\Crypt\Sm\Tests;

use phpseclib3\Crypt\Sm\SM2;
use PHPUnit\Framework\TestCase;

class Sm2Test extends TestCase
{
    private $sm2;
    private $publicKey;
    private $privateKey;

    protected function setUp(): void
    {
        $this->sm2 = new SM2();
        $keys = SM2::createKey('sm2p256v1');
        $this->publicKey = $keys['publicKey'];
        $this->privateKey = $keys['privateKey'];
    }

    public function testEncryptDecrypt()
    {
        $msg = 'hello world! 我是 antherd.';
        
        // 设置公钥并加密
        $this->sm2->loadKey($this->publicKey);
        $encrypted = $this->sm2->encrypt($msg);
        $this->assertNotEmpty($encrypted);
        $this->assertTrue(ctype_xdigit($encrypted));
        
        // 设置私钥并解密
        $this->sm2->loadKey($this->privateKey);
        $decrypted = $this->sm2->decrypt($encrypted);
        $this->assertEquals($msg, $decrypted);
    }

    public function testSignVerify()
    {
        $msg = 'hello world! 我是 antherd.';
        
        // 设置私钥并签名
        $this->sm2->loadKey($this->privateKey);
        $signature = $this->sm2->sign($msg);
        $this->assertNotEmpty($signature);
        $this->assertTrue(ctype_xdigit($signature));
        
        // 设置公钥并验证签名
        $this->sm2->loadKey($this->publicKey);
        $isValid = $this->sm2->verify($msg, $signature);
        $this->assertTrue($isValid);
        
        // 验证错误的签名
        $wrongSignature = str_repeat('0', strlen($signature));
        $isValid = $this->sm2->verify($msg, $wrongSignature);
        $this->assertFalse($isValid);
    }

    public function testEmptyInput()
    {
        // 测试空消息加密
        $this->sm2->loadKey($this->publicKey);
        $this->assertEquals('', $this->sm2->encrypt(''));
        
        $this->sm2->loadKey($this->privateKey);
        $this->assertEquals('', $this->sm2->decrypt(''));
        
        // 测试空消息签名
        $this->sm2->loadKey($this->privateKey);
        $signature = $this->sm2->sign('');
        $this->sm2->loadKey($this->publicKey);
        $this->assertTrue($this->sm2->verify('', $signature));
    }

    public function testInvalidKey()
    {
        $msg = 'test message';
        $invalidKey = str_repeat('0', 64);
        
        // 测试无效的公钥
        $this->expectException(\Exception::class);
        $this->sm2->loadKey($invalidKey);
        $this->sm2->encrypt($msg);
    }
}