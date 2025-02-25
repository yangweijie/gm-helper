<?php

namespace phpseclib3\Crypt\Sm\Tests;

use phpseclib3\Crypt\Sm\Sm2;
use phpseclib3\Crypt\Sm\Keypair;
use PHPUnit\Framework\TestCase;

class Sm2ExtendedTest extends TestCase
{
    private $keypair;
    private $publicKey;
    private $privateKey;
    private $sm2;

    protected function setUp(): void
    {
        $this->keypair = Keypair::generate();
        $this->publicKey = $this->keypair->getPublicKey();
        $this->privateKey = $this->keypair->getPrivateKey();
        $this->sm2 = new Sm2();
    }

    /**
     * 测试密钥生成的一致性和有效性
     */
    public function testKeyGeneration()
    {
        // 生成多个密钥对并验证其唯一性
        $keys = [];
        for ($i = 0; $i < 5; $i++) {
            $keypair = Keypair::generate();
            $publicKey = $keypair->getPublicKey();
            $privateKey = $keypair->getPrivateKey();

            // 验证密钥长度
            $this->assertTrue(strlen($publicKey) > 0);
            $this->assertTrue(strlen($privateKey) > 0);

            // 验证密钥唯一性
            $this->assertNotContains($publicKey, $keys, '公钥应该是唯一的');
            $keys[] = $publicKey;
        }
    }

    /**
     * 测试不同长度的消息加密
     */
    public function testDifferentMessageLengths()
    {
        $messages = [
            '', // 空消息
            'a', // 单字符
            str_repeat('a', 16), // 16字节
            str_repeat('a', 256), // 256字节
            str_repeat('a', 1024), // 1KB
        ];

        foreach ($messages as $msg) {
            $this->sm2->loadKey(['publicKey' => $this->publicKey]);
            $encrypted = $this->sm2->encrypt($msg);
            $this->sm2->loadKey(['privateKey' => $this->privateKey]);
            $decrypted = $this->sm2->decrypt($encrypted);
            $this->assertEquals($msg, $decrypted, '消息长度: ' . strlen($msg));
        }
    }

    /**
     * 测试特殊字符加密
     */
    public function testSpecialCharacters()
    {
        $specialChars = [
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", // 二进制数据
            '🌟🎉🔥💻', // Unicode表情
            '<script>alert("XSS")</script>', // HTML/JavaScript
            '\\n\\r\\t', // 转义字符
            '中文测试' // UTF-8字符
        ];

        foreach ($specialChars as $msg) {
            $this->sm2->loadKey(['publicKey' => $this->publicKey]);
            $encrypted = $this->sm2->encrypt($msg);
            $this->sm2->loadKey(['privateKey' => $this->privateKey]);
            $decrypted = $this->sm2->decrypt($encrypted);
            $this->assertEquals($msg, $decrypted);
        }
    }

    /**
     * 测试签名的一致性
     */
    public function testSignatureConsistency()
    {
        $message = 'Test message for signature consistency';
        $this->sm2->loadKey(['privateKey' => $this->privateKey]);
        
        // 同一消息多次签名应产生不同的签名（因为包含随机因子）
        $signature1 = $this->sm2->sign($message);
        $signature2 = $this->sm2->sign($message);
        $this->assertNotEquals($signature1, $signature2, '同一消息的两次签名应该不同');

        // 但所有签名都应该能被验证
        $this->sm2->loadKey(['publicKey' => $this->publicKey]);
        $this->assertTrue($this->sm2->verify($message, $signature1));
        $this->assertTrue($this->sm2->verify($message, $signature2));
    }

    /**
     * 测试签名验证的边界情况
     */
    public function testSignatureEdgeCases()
    {
        $message = 'Test message';
        $this->sm2->loadKey(['privateKey' => $this->privateKey]);
        $signature = $this->sm2->sign($message);

        $this->sm2->loadKey(['publicKey' => $this->publicKey]);
        // 测试消息被修改的情况
        $modifiedMessage = $message . ' modified';
        $this->assertFalse($this->sm2->verify($modifiedMessage, $signature));

        // 测试签名被修改的情况
        $modifiedSignature = substr($signature, 0, -1) . '1';
        $this->assertFalse($this->sm2->verify($message, $modifiedSignature));

        // 测试使用错误的公钥
        $wrongKeypair = Keypair::generate();
        $wrongPublicKey = $wrongKeypair->getPublicKey();
        $this->sm2->loadKey(['publicKey' => $wrongPublicKey]);
        $this->assertFalse($this->sm2->verify($message, $signature));
    }

    /**
     * 测试性能
     */
    public function testPerformance()
    {
        $message = str_repeat('a', 1024); // 1KB消息

        $startTime = microtime(true);
        
        // 执行10次加密/解密操作
        for ($i = 0; $i < 10; $i++) {
            $sm2 = new Sm2();
            $sm2->loadKey(['publicKey' => $this->publicKey]);
            $encrypted = $sm2->encrypt($message);
            $sm2->loadKey(['privateKey' => $this->privateKey]);
            $decrypted = $sm2->decrypt($encrypted);
        }
        
        $encryptionTime = microtime(true) - $startTime;
        $this->assertLessThan(10, $encryptionTime, '10次1KB消息的加密/解密操作应在10秒内完成');

        $startTime = microtime(true);
        
        // 执行10次签名/验证操作
        for ($i = 0; $i < 10; $i++) {
            $sm2 = new Sm2();
            $sm2->loadKey(['privateKey' => $this->privateKey]);
            $signature = $sm2->sign($message);
            $sm2->loadKey(['publicKey' => $this->publicKey]);
            $this->assertTrue($sm2->verify($message, $signature));
        }
        
        $signTime = microtime(true) - $startTime;
        $this->assertLessThan(10, $signTime, '10次1KB消息的签名/验证操作应在10秒内完成');
    }
}