<?php
namespace Poirot\OAuth2\Crypt\Aes;

use Poirot\OAuth2\Interfaces\iEncrypt;


/**
 * AES-128-CBC Encryption
 */
class Crypt
    implements iEncrypt
{
    const CIPHER = MCRYPT_RIJNDAEL_128;
    const MODE   = MCRYPT_MODE_CBC;

    protected $key;
    protected $iv;


    /**
     * Crypt constructor.
     * 
     * @param $key
     * @param KeyIV $iv
     */
    function __construct($key, $iv)
    {
        $this->key = (string) $key;
        $this->iv  = (string) $iv;
    }
    
    /**
     * Encrypt
     *
     * @param $unencryptedData
     *
     * @return string
     */
    function encrypt($unencryptedData)
    {
        return trim(base64_encode(str_rot13(
            mcrypt_encrypt(self::CIPHER, $this->key, $unencryptedData, self::MODE, $this->iv)
        )));
    }

    /**
     * Decrypt
     *
     * @param $encryptedData
     *
     * @return string
     * @throws \Exception
     */
    function decrypt($encryptedData)
    {
        return trim(mcrypt_decrypt(
            self::CIPHER
            , $this->key
            , str_rot13(base64_decode($encryptedData))
            , self::MODE
            , $this->iv
        ));
    }
}
