<?php
namespace yangweijie;
use Rtgm\sm\Rtsm2;
use Rtgm\util\MyAsn1;
use Rtgm\util\SmSignFormatRS;

/**
 * 国密2 优化版，支持补04 和base64 输出
 */

 Class Sm2 extends Rtsm2
 {
    public function doEncrypt($document, $publicKey, $model = C1C3C2, $outFormat = 'hex', $appendZeroFour = false)
    {
        $ret = parent::doEncrypt($document, $publicKey, $model);
        if ($outFormat == 'hex') {
            if($appendZeroFour){
                return '04'.$ret;
            }else{
                return $ret;
            }
        }else{
            if($appendZeroFour){
                $ret = '04'.$ret;
            }
            return base64_encode(hex2bin($ret))
        }
    }

    /**
     * SM2 签名明文16进制密码, 如提供的base64的，可使用 bin2hex(base64_decode($privateKey))
     *
     */
    public function doSign($document, $privateKey, $userId = null, $outFormat = 'hex', $toRS = false)
    {
        $ret = parent::doSign($document, $privateKey, $userId);
        if($outFormat === 'hex'){
            return $toRs? SmSignFormatRS::asn1_to_rs($ret, 'hex') : $ret;
        }else{
            $ret = $toRs? SmSignFormatRS::asn1_to_rs($ret, 'hex') : $ret;
            return bin2hex(base64_decode($ret));
        }
    }

    function asn1ToHexPublic(string $asn): string
    {
        static $cache = [];
        if(isset($cache[$asn])){
            return $cache[$asn];
        }
        $publicKey = MyAsn1::decode($asn, 'base64')[1];
        $cache[$asn] = $publicKey;
        return $publicKey;
    }

    function asn1ToHexPrivate(string $asn) : string{
        static $cache = [];
        if(isset($cache[$asn])){
            return $cache[$asn];
        }
        $rxPrivateKey = MyAsn1::decode($asn, 'base64')[2];
        if(str_starts_with($rxPrivateKey, '30')){
            $rxPrivateKey = MyAsn1::decode($rxPrivateKey, 'hex')[1];
        }
        $cache[$asn] = $rxPrivateKey;
        return $rxPrivateKey;
    }
 }