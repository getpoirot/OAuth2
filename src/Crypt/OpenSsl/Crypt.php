<?php
namespace Poirot\OAuth2\Crypt\OpenSsl;

use Poirot\OAuth2\Interfaces\iEncrypt;

use Poirot\Std\ConfigurableSetter;


class Crypt 
    implements iEncrypt
{
    /** @var KeyCrypt */
    protected $privateKey;
    /** @var KeyCrypt */
    protected $publicKey;

    
    /**
     * Crypt constructor.
     * 
     * @param KeyCrypt|null $privateKey
     * @param KeyCrypt|null $publicKey
     */
    function __construct(KeyCrypt $privateKey = null, KeyCrypt $publicKey = null)
    {
        ($privateKey === null) ?: $this->setPrivateKey($privateKey);
        ($publicKey === null)  ?: $this->setPublicKey($publicKey);
    }

    /**
     * Encrypt data with a private key.
     *
     * @param string $unencryptedData
     *
     * @return string
     * @throws \LogicException
     */
    function encrypt($unencryptedData)
    {
        $privateKey = openssl_pkey_get_private($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase());
        $privateKeyDetails = @openssl_pkey_get_details($privateKey);
        if ($privateKeyDetails === null)
            throw new \LogicException(
                sprintf('Could not get details of private key: %s', $this->privateKey->getKeyPath())
            );

        $chunkSize = ceil($privateKeyDetails['bits'] / 8) - 11;
        $output = '';

        while ($unencryptedData) {
            $chunk = substr($unencryptedData, 0, $chunkSize);
            $unencryptedData = substr($unencryptedData, $chunkSize);
            if (openssl_private_encrypt($chunk, $encrypted, $privateKey) === false)
                throw new \LogicException('Failed to encrypt data');
      
            $output .= $encrypted;
        }
        
        openssl_pkey_free($privateKey);

        return base64_encode($output);
    }

    /**
     * Decrypt data with a public key.
     *
     * @param string $encryptedData
     *
     * @return string
     * @throws \LogicException
     */
    function decrypt($encryptedData)
    {
        $publicKey = openssl_pkey_get_public($this->publicKey->getKeyPath());
        $publicKeyDetails = @openssl_pkey_get_details($publicKey);
        if ($publicKeyDetails === null)
            throw new \LogicException(
                sprintf('Could not get details of public key: %s', $this->publicKey->getKeyPath())
            );

        $chunkSize = ceil($publicKeyDetails['bits'] / 8);
        $output = '';

        $encryptedData = base64_decode($encryptedData);

        while ($encryptedData) {
            $chunk = substr($encryptedData, 0, $chunkSize);
            $encryptedData = substr($encryptedData, $chunkSize);
            if (openssl_public_decrypt($chunk, $decrypted, $publicKey/*, OPENSSL_PKCS1_OAEP_PADDING*/) === false)
                throw new \LogicException('Failed to decrypt data');
            
            $output .= $decrypted;
        }
        
        openssl_pkey_free($publicKey);

        return $output;
    }

    
    // Options:
    
    /**
     * Set path to private key
     *
     * @param KeyCrypt $privateKey
     * 
     * @return $this
     */
    function setPrivateKey(KeyCrypt $privateKey)
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    /**
     * Set path to public key
     *
     * @param KeyCrypt $publicKey
     * 
     * @return $this
     */
    function setPublicKey(KeyCrypt $publicKey)
    {
        $this->publicKey = $publicKey;
        return $this;
    }
}
