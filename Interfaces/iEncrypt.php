<?php
namespace Poirot\OAuth2\Interfaces;

interface iEncrypt
{
    /**
     * Encrypt
     * 
     * @param $unencryptedData
     * 
     * @return string
     */
    function encrypt($unencryptedData);

    /**
     * Decrypt
     *
     * @param $encryptedData
     *
     * @return string
     */
    function decrypt($encryptedData);
}
