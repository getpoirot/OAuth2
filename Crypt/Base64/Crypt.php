<?php
namespace Poirot\OAuth2\Crypt\Base64;

use Poirot\OAuth2\Interfaces\iEncrypt;

class Crypt
    implements iEncrypt
{
    /**
     * Encrypt
     *
     * @param $unencryptedData
     *
     * @return string
     */
    function encrypt($unencryptedData)
    {
        return base64_encode($unencryptedData);
    }

    /**
     * Decrypt
     *
     * @param $encryptedData
     *
     * @return string
     */
    function decrypt($encryptedData)
    {
        return base64_decode($encryptedData);
    }
}
