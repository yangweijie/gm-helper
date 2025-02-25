<?php

namespace phpseclib3\Crypt\Sm\Tests;
use phpseclib3\Crypt\Sm\SM4;
use PHPUnit\Framework\TestCase;

class Sm4Test extends TestCase
{
    public function testGenerateKeyHex()
    {
        $key = SM4::generateKeyHex();
        $this->assertEquals(32, strlen($key));
        $this->assertTrue(ctype_xdigit($key));
    }

    public function testEncryptDecrypt()
    {
        $msg = 'hello world! 我是 antherd.';
        $key = '0123456789abcdeffedcba9876543210';
        $sm4 = new SM4();

        // 默认模式（ECB + PKCS5Padding）
        $sm4->setKey($key);
        $encrypted = bin2hex($sm4->encrypt($msg));
        $decrypted = $sm4->decrypt(hex2bin($encrypted));
        $this->assertEquals($msg, $decrypted);

        // 无填充模式（使用16字节倍数长度的数据）
        $msg16 = str_pad($msg, ceil(strlen($msg) / 16) * 16, "\0");
        $sm4->setPadding('none');
        $encrypted = bin2hex($sm4->encrypt($msg16));
        $decrypted = $sm4->decrypt(hex2bin($encrypted));
        $this->assertEquals($msg16, $decrypted);

        // CBC模式
        $sm4->setMode('cbc');
        $sm4->setPadding('pkcs5');
        $sm4->setIV(hex2bin('fedcba98765432100123456789abcdef'));
        $encrypted = bin2hex($sm4->encrypt($msg));
        $decrypted = $sm4->decrypt(hex2bin($encrypted));
        $this->assertEquals($msg, $decrypted);
    }

    public function testEmptyInput()
    {
        $key = '0123456789abcdeffedcba9876543210';
        $sm4 = new SM4();
        $sm4->setKey($key);
        $this->assertEquals('', bin2hex($sm4->encrypt('')));
        $this->assertEquals('', $sm4->decrypt(hex2bin('')));
    }

    public function testInvalidKeyLength()
    {
        $sm4 = new SM4();
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Invalid key length');
        $sm4->setKey('123');
    }

    public function testInvalidIvLength()
    {
        $msg = 'hello world! 我是 antherd.';
        $key = '0123456789abcdeffedcba9876543210';
        $sm4 = new SM4();
        $sm4->setKey($key);
        $sm4->setMode('cbc');

        // 测试IV长度不正确的情况
        $this->expectException('\Exception');
        $sm4->setIV(hex2bin('0123456789abcdef0123456789abcdef00')); // 17字节，超过块大小
    }
}