<?php

namespace phpseclib3\Crypt\Sm\Tests;

use phpseclib3\Crypt\Sm\Sm3;
use PHPUnit\Framework\TestCase;

class Sm3ExtendedTest extends TestCase
{
    /**
     * 测试不同长度的输入数据
     */
    public function testDifferentInputLengths()
    {
        // 测试短输入
        $shortInput = 'a';
        $shortHash = Sm3::hash($shortInput);
        $this->assertEquals(64, strlen($shortHash));
        $this->assertTrue(ctype_xdigit($shortHash));

        // 测试空字符串
        $emptyHash = Sm3::hash('');
        $this->assertEquals('', $emptyHash);

        // 测试长输入
        $longInput = str_repeat('abcdefgh', 1000);
        $longHash = Sm3::hash($longInput);
        $this->assertEquals(64, strlen($longHash));
        $this->assertTrue(ctype_xdigit($longHash));
    }

    /**
     * 测试特殊字符输入
     */
    public function testSpecialCharacters()
    {
        // 测试二进制数据
        $binaryData = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        $binaryHash = Sm3::hash($binaryData);
        $this->assertEquals(64, strlen($binaryHash));
        $this->assertTrue(ctype_xdigit($binaryHash));

        // 测试特殊Unicode字符
        $unicodeData = '🌟🎉🔥💻';
        $unicodeHash = Sm3::hash($unicodeData);
        $this->assertEquals(64, strlen($unicodeHash));
        $this->assertTrue(ctype_xdigit($unicodeHash));
    }

    /**
     * 测试哈希值的一致性
     */
    public function testHashConsistency()
    {
        $testData = [
            'Hello, World!',
            '中文测试',
            str_repeat('test', 100),
            "\x00\x01\x02\x03"
        ];

        foreach ($testData as $data) {
            // 同一数据多次哈希应该得到相同的结果
            $hash1 = Sm3::hash($data);
            $hash2 = Sm3::hash($data);
            $this->assertEquals($hash1, $hash2, '同一数据的哈希值应该相同');

            // 稍微改变数据应该得到不同的哈希值
            $modifiedData = $data . 'x';
            $modifiedHash = Sm3::hash($modifiedData);
            $this->assertNotEquals($hash1, $modifiedHash, '不同数据的哈希值应该不同');
        }
    }

    /**
     * 测试性能
     */
    public function testPerformance()
    {
        $sizes = [1024, 10240, 102400]; // 1KB, 10KB, 100KB

        foreach ($sizes as $size) {
            $data = str_repeat('a', $size);
            $startTime = microtime(true);
            
            // 执行100次哈希
            for ($i = 0; $i < 100; $i++) {
                Sm3::hash($data);
            }
            
            $endTime = microtime(true);
            $duration = $endTime - $startTime;
            
            // 确保性能在合理范围内
            $this->assertLessThan(10, $duration, sprintf('%d bytes 数据的100次哈希操作应在10秒内完成', $size));
        }
    }
}