<?php
class SM2Wrapper {
    private $tempDir;
    private $gmsslPath;

    /**
     * 构造函数
     *
     * @param string|null $tempDir  临时目录路径，默认为系统临时目录
     * @param string|null $gmsslPath gmssl 命令的完整路径或命令名称，默认为 "gmssl"
     */
    public function __construct($tempDir = null, $gmsslPath = null) {
        $this->tempDir = $tempDir ? rtrim($tempDir, DIRECTORY_SEPARATOR) : sys_get_temp_dir();
        $this->gmsslPath = $gmsslPath ? $gmsslPath : 'gmssl';
    }

    /**
     * 设置临时目录
     *
     * @param string $tempDir 临时目录路径
     */
    public function setTempDir($tempDir) {
        $this->tempDir = rtrim($tempDir, DIRECTORY_SEPARATOR);
    }

    /**
     * 设置 gmssl 工具的路径
     *
     * @param string $gmsslPath gmssl 命令的完整路径或命令名称
     */
    public function setGmsslPath($gmsslPath) {
        $this->gmsslPath = $gmsslPath;
    }

    /**
     * 生成唯一的临时文件路径
     *
     * @param string $prefix 文件名前缀
     * @return string 临时文件路径
     */
    private function getTempFilePath($prefix) {
        return $this->tempDir . DIRECTORY_SEPARATOR . $prefix . '_' . uniqid() . '.tmp';
    }

    /**
     * 使用公钥字符串对数据进行加密
     *
     * @param string $data 待加密的数据
     * @param string $publicKey 公钥字符串
     * @return string 加密后的数据（二进制内容）
     */
    public function encrypt($data, $publicKey) {
        $publicKeyPath = $this->getTempFilePath('sm2pubkey');
        $dataPath = $this->getTempFilePath('data');
        $encryptedPath = $this->getTempFilePath('encrypted');

        file_put_contents($publicKeyPath, $publicKey);
        file_put_contents($dataPath, $data);

        // 使用 gmssl 进行加密，注意：-pubin 标识传入的是公钥
        shell_exec("\"{$this->gmsslPath}\" pkeyutl -encrypt -inkey \"$publicKeyPath\" -pubin -in \"$dataPath\" -out \"$encryptedPath\"");

        $encryptedData = file_get_contents($encryptedPath);

        // 清理临时文件
        unlink($publicKeyPath);
        unlink($dataPath);
        unlink($encryptedPath);

        return $encryptedData;
    }

    /**
     * 使用私钥字符串对加密数据进行解密
     *
     * @param string $encryptedData 待解密的加密数据（二进制内容）
     * @param string $privateKey 私钥字符串
     * @return string 解密后的数据
     */
    public function decrypt($encryptedData, $privateKey) {
        $privateKeyPath = $this->getTempFilePath('sm2key');
        $encryptedPath = $this->getTempFilePath('encrypted');
        $decryptedPath = $this->getTempFilePath('decrypted');

        file_put_contents($privateKeyPath, $privateKey);
        file_put_contents($encryptedPath, $encryptedData);

        // 使用 gmssl 进行解密
        shell_exec("\"{$this->gmsslPath}\" pkeyutl -decrypt -inkey \"$privateKeyPath\" -in \"$encryptedPath\" -out \"$decryptedPath\"");

        $decryptedData = file_get_contents($decryptedPath);

        // 清理临时文件
        unlink($privateKeyPath);
        unlink($encryptedPath);
        unlink($decryptedPath);

        return $decryptedData;
    }

    /**
     * 使用私钥字符串对数据进行 SM2 签名
     *
     * @param string $data 待签名数据
     * @param string $privateKey 私钥字符串
     * @return string 签名结果（二进制内容）
     */
    public function sign($data, $privateKey) {
        $privateKeyPath = $this->getTempFilePath('sm2key');
        $dataPath = $this->getTempFilePath('data');
        $signaturePath = $this->getTempFilePath('signature');

        file_put_contents($privateKeyPath, $privateKey);
        file_put_contents($dataPath, $data);

        // 进行签名操作
        shell_exec("\"{$this->gmsslPath}\" pkeyutl -sign -inkey \"$privateKeyPath\" -in \"$dataPath\" -out \"$signaturePath\"");

        $signature = file_get_contents($signaturePath);

        // 清理临时文件
        unlink($privateKeyPath);
        unlink($dataPath);
        unlink($signaturePath);

        return $signature;
    }

    /**
     * 使用公钥字符串验证 SM2 签名
     *
     * @param string $data 待验证数据
     * @param string $signature 签名内容（二进制内容）
     * @param string $publicKey 公钥字符串
     * @return bool 验证成功返回 true，否则 false
     */
    public function verify($data, $signature, $publicKey) {
        $publicKeyPath = $this->getTempFilePath('sm2pubkey');
        $dataPath = $this->getTempFilePath('data');
        $signaturePath = $this->getTempFilePath('signature');

        file_put_contents($publicKeyPath, $publicKey);
        file_put_contents($dataPath, $data);
        file_put_contents($signaturePath, $signature);

        // 进行签名验证，并将错误输出捕获
        $result = shell_exec("\"{$this->gmsslPath}\" pkeyutl -verify -pubin -inkey \"$publicKeyPath\" -in \"$dataPath\" -sigfile \"$signaturePath\" 2>&1");

        // 清理临时文件
        unlink($publicKeyPath);
        unlink($dataPath);
        unlink($signaturePath);

        return strpos($result, 'Signature Verified Successfully') !== false;
    }

    /**
     * 将 Base64 字符串拼接为标准的 SM2 私钥 PEM 格式字符串
     *
     * @param string $base64String Base64 编码后的私钥内容
     * @return string 格式化后的私钥字符串
     */
    public static function formatPrivateKey($base64String) {
        $formattedKey = "-----BEGIN PRIVATE KEY-----\n";
        $formattedKey .= chunk_split($base64String, 64, "\n");
        $formattedKey .= "-----END PRIVATE KEY-----\n";
        return $formattedKey;
    }

    /**
     * 将 Base64 字符串拼接为标准的 SM2 公钥 PEM 格式字符串
     *
     * @param string $base64String Base64 编码后的公钥内容
     * @return string 格式化后的公钥字符串
     */
    public static function formatPublicKey($base64String) {
        $formattedKey = "-----BEGIN PUBLIC KEY-----\n";
        $formattedKey .= chunk_split($base64String, 64, "\n");
        $formattedKey .= "-----END PUBLIC KEY-----\n";
        return $formattedKey;
    }
}