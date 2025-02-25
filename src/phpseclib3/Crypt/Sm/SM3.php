<?php

namespace phpseclib3\Crypt\Sm;

class SM3
{
    private const IV = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ];

    private const T = [
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
    ];

    public static function hash($message)
    {
        if (empty(trim($message))) {
            return '';
        }
        $sm3 = new self();
        return $sm3->hashMessage($message);
    }

    private function hashMessage($message)
    {
        $padded = $this->pad($message);
        $blocks = $this->iterate($padded);
        
        $v = self::IV;
        foreach ($blocks as $block) {
            $v = $this->compress($v, $block);
        }
        
        $hash = '';
        foreach ($v as $word) {
            $hash .= str_pad(dechex($word), 8, '0', STR_PAD_LEFT);
        }
        
        return substr($hash, 0, 64);
    }

    private function pad($message)
    {
        $length = strlen($message);
        $l = $length * 8;
        $k = (447 - $l) % 512;
        if ($k < 0) {
            $k += 512;
        }
        
        $bin = $message . chr(0x80);
        $bin .= str_repeat(chr(0), ($k - 7) / 8);
        $bin .= pack('J', $l);
        
        return $bin;
    }

    private function iterate($message)
    {
        $blocks = str_split($message, 64);
        $result = [];
        
        foreach ($blocks as $block) {
            $words = array_values(unpack('N*', $block));
            $result[] = $words;
        }
        
        return $result;
    }

    private function compress($v, $b)
    {
        $w = array_pad($b, 68, 0);
        $w1 = array_pad([], 64, 0);
        
        for ($j = 16; $j < 68; $j++) {
            $w[$j] = (int)($this->p1((int)($w[$j-16] ^ $w[$j-9] ^ $this->rotateLeft($w[$j-3], 15))) ^
                     $this->rotateLeft($w[$j-13], 7) ^ $w[$j-6]);
        }
        
        for ($j = 0; $j < 64; $j++) {
            $w1[$j] = (int)($w[$j] ^ $w[$j+4]);
        }
        
        list($a, $b, $c, $d, $e, $f, $g, $h) = $v;
        
        for ($j = 0; $j < 64; $j++) {
            $ss1 = (int)$this->rotateLeft((int)($this->rotateLeft($a, 12) + $e + $this->rotateLeft(self::T[$j], $j)), 7);
            $ss2 = (int)($ss1 ^ $this->rotateLeft($a, 12));
            $tt1 = (int)($this->ff($j, $a, $b, $c) + $d + $ss2 + $w1[$j]);
            $tt2 = (int)($this->gg($j, $e, $f, $g) + $h + $ss1 + $w[$j]);
            $d = (int)$c;
            $c = (int)$this->rotateLeft($b, 9);
            $b = (int)$a;
            $a = (int)$tt1;
            $h = (int)$g;
            $g = (int)$this->rotateLeft($f, 19);
            $f = (int)$e;
            $e = (int)$this->p0($tt2);
        }
        
        return [
            $a ^ $v[0], $b ^ $v[1], $c ^ $v[2], $d ^ $v[3],
            $e ^ $v[4], $f ^ $v[5], $g ^ $v[6], $h ^ $v[7]
        ];
    }

    private function rotateLeft($x, $n)
    {
        $n = $n & 31; // 确保位移值在 0-31 之间
        return (($x << $n) | ($x >> (32 - $n))) & 0xffffffff;
    }

    private function ff($j, $x, $y, $z)
    {
        return $j < 16 ? $x ^ $y ^ $z : ($x & $y) | ($x & $z) | ($y & $z);
    }

    private function gg($j, $x, $y, $z)
    {
        return $j < 16 ? $x ^ $y ^ $z : ($x & $y) | (~$x & $z);
    }

    private function p0($x)
    {
        return $x ^ $this->rotateLeft($x, 9) ^ $this->rotateLeft($x, 17);
    }

    private function p1($x)
    {
        return $x ^ $this->rotateLeft($x, 15) ^ $this->rotateLeft($x, 23);
    }
}