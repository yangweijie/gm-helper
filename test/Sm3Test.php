<?php

require __DIR__ . '/../vendor/autoload.php';
// namespace phpseclib3\Crypt\Sm\Tests;

use phpseclib3\Crypt\Sm\SM3;
use PHPUnit\Framework\TestCase;

class Sm3Test extends TestCase
{
    public function testHash()
    {
        $message = 'hello world! 我是 antherd.';
        $hash = Sm3::hash($message);
        
        // 验证哈希值长度（SM3输出256位，即64个十六进制字符）
        $this->assertEquals(64, strlen($hash));
        // 验证哈希值是否为有效的十六进制字符串
        $this->assertTrue(ctype_xdigit($hash));
        
        // 验证相同输入产生相同的哈希值
        $this->assertEquals($hash, Sm3::hash($message));
        
        // 验证不同输入产生不同的哈希值
        $differentMessage = 'different message';
        $this->assertNotEquals($hash, Sm3::hash($differentMessage));
    }
    
    public function testEmptyInput()
    {
        // 验证空输入
        $this->assertEquals('', Sm3::hash(''));
        $this->assertEquals('', Sm3::hash('  '));
    }
}