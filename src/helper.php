<?php
function stringToBytes($string)
{

    return unpack('C*', $string);

}

function bytesToString($bytes)
{

    return vsprintf(str_repeat('%c', count($bytes)), $bytes);

}


function formatHex($dec)
{

    $hex = gmp_strval(gmp_init($dec, 10), 16);
    $len = strlen($hex);
    if ($len == 64) {
        return $hex;
    }
    if ($len < 64){
        $hex = str_pad($hex, 64, "0", STR_PAD_LEFT);
    }else {
        $hex = substr($hex, $len - 64, 64);
    }

    return $hex;
}