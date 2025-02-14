# gm-helper

基于 phplibec 扩展的php7国密常用算法 sm2sm3sm4，支持有openssl扩展支持时用openssl（装gmssl）

sm2 参考了 [lpilp/simplesm2](https://github.com/lpilp/simplesm2)

## 安装

~~~ bash
composer require yangweijie/gm-helper
~~~

## 使用

### 密钥获取 hex 格式字符串

~~~php
use sm\sm2\Formats\Signature\ASN1;

$hex = ASN1::decode($pem);

~~~

### 加密 、解密

#### 加密解密模式

- C1C3C2
- C1C2C3

#### 加密

~~~php
$publicKey = '04eb4b8bbe15e3ad94b85196adc2c6f694436b3c1336170fd1daac8b10d2b8824ada9687c138fb81590e0f66ab9678161732ac0d7866b169e76b74483285f2bc04';
$ssm2 = new Sm2();
$ssm2->setFixForeignKeyFlag(true); //
$data = 'hello123';
$val = $ssm2->encrypt($publicKey, $data, 'C1C2C3');
trace($val);

~~~

### 解密

~~~php
$privateKey = '0bc1c1d2771b64ba1922d72f8a451cd09a82176f74d975d484ec62c862176b75';
$val = $ssm2->decrypt($privateKey,$val, 'C1C2C3',true);
trace($val);
~~~

### 签名

~~~php
$userId = '1234567812345678';

$sign = $ssm2->sign($data, $privateKey, $publicKey, $userId);
~~~

## QA
