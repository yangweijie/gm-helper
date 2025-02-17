<?php
// 假设已经生成密钥文件，并将内容读取为字符串
$privateKeyString = file_get_contents('sm2key.pem');
$publicKeyString = file_get_contents('sm2pubkey.pem');

// 指定 gmssl 的路径，例如在 Windows 上的完整路径（如果已加入环境变量可以直接使用 "gmssl"）
$gmsslPath = 'C:\\Program Files\\GmSSL\\bin\\gmssl.exe';

// 指定临时文件存放目录
$tempDir = 'C:\\temp';

$sm2 = new SM2Wrapper($tempDir, $gmsslPath);

$data = "需要加密的数据";

// 加密与解密
$encrypted = $sm2->encrypt($data, $publicKeyString);
$decrypted = $sm2->decrypt($encrypted, $privateKeyString);
echo "解密后的数据：" . $decrypted . PHP_EOL;

// 签名与验证
$signature = $sm2->sign($data, $privateKeyString);
if ($sm2->verify($data, $signature, $publicKeyString)) {
    echo "签名验证成功";
} else {
    echo "签名验证失败";
}