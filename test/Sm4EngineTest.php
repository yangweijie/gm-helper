<?php

namespace phpseclib3\Crypt\Sm\Tests;

use phpseclib3\Crypt\Sm\SM4;
use PHPUnit\Framework\TestCase;

class Sm4EngineTest extends TestCase
{
    private $sm4;
    private $key;
    private $plaintext;

    protected function setUp(): void
    {
        $this->sm4 = new SM4();
        $this->key = str_repeat('a', 32); // 32字节的十六进制密钥
        $this->plaintext = 'Hello, World!';
    }

    public function testOpenSSLEngineEnabled()
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('OpenSSL extension not available.');
        }

        $this->sm4->setKey($this->key);
        $this->sm4->setPreferredEngine(SM4::ENGINE_OPENSSL);

        $encrypted = $this->sm4->encrypt($this->plaintext);
        $decrypted = $this->sm4->decrypt($encrypted);

        $this->assertEquals($this->plaintext, $decrypted);
        $this->assertEquals('OpenSSL', $this->sm4->getEngine());
    }

    public function testInternalEngineFallback()
    {
        // 模拟OpenSSL不可用的情况
        if (extension_loaded('openssl')) {
            $this->markTestSkipped('This test requires OpenSSL to be disabled.');
        }

        $this->sm4->setKey($this->key);
        $this->sm4->setPreferredEngine(SM4::ENGINE_OPENSSL);

        $encrypted = $this->sm4->encrypt($this->plaintext);
        $decrypted = $this->sm4->decrypt($encrypted);

        $this->assertEquals($this->plaintext, $decrypted);
        $this->assertEquals('Internal', $this->sm4->getEngine());
    }

    public function testForceInternalEngine()
    {
        $this->sm4->setKey($this->key);
        $this->sm4->setPreferredEngine(SM4::ENGINE_INTERNAL);

        $encrypted = $this->sm4->encrypt($this->plaintext);
        $decrypted = $this->sm4->decrypt($encrypted);

        $this->assertEquals($this->plaintext, $decrypted);
        $this->assertEquals('Internal', $this->sm4->getEngine());
    }

    public function testEngineConsistency()
    {
        $this->sm4->setKey($this->key);

        // 使用OpenSSL引擎加密
        $this->sm4->setPreferredEngine(SM4::ENGINE_OPENSSL);
        $encryptedOpenSSL = $this->sm4->encrypt($this->plaintext);

        // 使用内部引擎加密
        $this->sm4->setPreferredEngine(SM4::ENGINE_INTERNAL);
        $encryptedInternal = $this->sm4->encrypt($this->plaintext);

        // 验证两种引擎的加密结果是否一致
        $this->assertEquals($encryptedInternal, $encryptedOpenSSL, '不同引擎的加密结果应该一致');

        // 使用OpenSSL引擎解密
        $this->sm4->setPreferredEngine(SM4::ENGINE_OPENSSL);
        $decryptedOpenSSL = $this->sm4->decrypt($encryptedOpenSSL);

        // 使用内部引擎解密
        $this->sm4->setPreferredEngine(SM4::ENGINE_INTERNAL);
        $decryptedInternal = $this->sm4->decrypt($encryptedInternal);

        // 解密结果应该与原始数据一致
        $this->assertEquals($this->plaintext, $decryptedOpenSSL);
        $this->assertEquals($this->plaintext, $decryptedInternal);
    }
}