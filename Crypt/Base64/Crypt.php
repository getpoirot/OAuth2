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
        return urlencode(base64_encode(gzcompress($unencryptedData, 9)));
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
        $data = base64_decode(urldecode($encryptedData));
        if (false === $decrypt = @gzuncompress($data))
            throw new \Exception('Given Encrypted Data is Malformed.');

        return $decrypt;
    }
}
