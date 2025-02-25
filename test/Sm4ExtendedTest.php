<?php

namespace phpseclib3\Crypt\Sm\Tests;

use phpseclib3\Crypt\Sm\Sm4;
use PHPUnit\Framework\TestCase;

class Sm4ExtendedTest extends TestCase
{
    /**
     * 测试不同长度的输入数据
     */
    public function testDifferentInputLengths()
    {
        $key = '0123456789abcdeffedcba9876543210';
        $sm4 = new Sm4();
        $sm4->setKey($key);
        
        // 测试短输入
        $shortInput = 'a';
        $encrypted = $sm4->encrypt($shortInput);
        $this->assertEquals($shortInput, $sm4->decrypt($encrypted));
        
        // 测试16字节输入（刚好一个块）
        $blockSizeInput = '1234567890123456';
        $encrypted = $sm4->encrypt($blockSizeInput);
        $this->assertEquals($blockSizeInput, $sm4->decrypt($encrypted));
        
        // 测试长输入
        $longInput = str_repeat('abcdefgh', 100);
        $encrypted = $sm4->encrypt($longInput);
        $this->assertEquals($longInput, $sm4->decrypt($encrypted));
    }

    /**
     * 测试不同模式和填充的组合
     */
    public function testModePaddingCombinations()
    {
        $key = '0123456789abcdeffedcba9876543210';
        $iv = 'fedcba98765432100123456789abcdef';
        $data = str_repeat('A', 16); // 使用16字节的数据以满足无填充模式的要求

        $combinations = [
            ['mode' => 'ecb', 'padding' => 'PKCS5Padding'],
            ['mode' => 'ecb', 'padding' => 'none'],
            ['mode' => 'cbc', 'padding' => 'PKCS5Padding', 'iv' => $iv],
            ['mode' => 'cbc', 'padding' => 'none', 'iv' => $iv]
        ];

        foreach ($combinations as $options) {
            $sm4 = new Sm4();
            $sm4->setKey($key);
            if (isset($options['mode'])) {
                $sm4->setMode($options['mode']);
            }
            if (isset($options['padding'])) {
                $sm4->setPadding($options['padding']);
            }
            if (isset($options['iv'])) {
                $sm4->setIV($options['iv']);
            }
            
            $encrypted = $sm4->encrypt($data);
            $decrypted = $sm4->decrypt($encrypted);
            $this->assertEquals($data, $decrypted);
        }
    }

    /**
     * 测试特殊字符的加密解密
     */
    public function testSpecialCharacters()
    {
        $key = '0123456789abcdeffedcba9876543210';
        $sm4 = new Sm4();
        $sm4->setKey($key);
        
        $specialChars = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\";
        $encrypted = $sm4->encrypt($specialChars);
        $this->assertEquals($specialChars, $sm4->decrypt($encrypted));
    }

    /**
     * 测试不同IV的影响
     */
    public function testDifferentIVs()
    {
        $key = '0123456789abcdeffedcba9876543210';
        $data = 'Test data for different IVs';
        $iv1 = '1234567890abcdef';
        $iv2 = 'abcdef1234567890';

        $sm4_1 = new Sm4();
        $sm4_1->setKey($key);
        $sm4_1->setMode('cbc');
        $sm4_1->setIV($iv1);

        $sm4_2 = new Sm4();
        $sm4_2->setKey($key);
        $sm4_2->setMode('cbc');
        $sm4_2->setIV($iv2);

        $encrypted1 = $sm4_1->encrypt($data);
        $encrypted2 = $sm4_2->encrypt($data);

        $this->assertNotEquals($encrypted1, $encrypted2);
        $this->assertEquals($data, $sm4_1->decrypt($encrypted1));
        $this->assertEquals($data, $sm4_2->decrypt($encrypted2));
    }

    /**
     * 测试密钥差异对加密结果的影响
     */
    public function testKeyDifference()
    {
        $key1 = '0123456789abcdeffedcba9876543210';
        $key2 = 'fedcba98765432100123456789abcdef';
        $data = 'Test data for different keys';

        $sm4_1 = new Sm4();
        $sm4_1->setKey($key1);

        $sm4_2 = new Sm4();
        $sm4_2->setKey($key2);

        $encrypted1 = $sm4_1->encrypt($data);
        $encrypted2 = $sm4_2->encrypt($data);

        $this->assertNotEquals($encrypted1, $encrypted2);
        $this->assertEquals($data, $sm4_1->decrypt($encrypted1));
        $this->assertEquals($data, $sm4_2->decrypt($encrypted2));
    }
}