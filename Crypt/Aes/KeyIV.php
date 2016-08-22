<?php
namespace Poirot\OAuth2\Crypt\Aes;


/**
 * Persistent KeyIV
 * 
 */
class KeyIV
{
    /**
     * KeyIV constructor.
     *
     * @param string $filePath To store iv key once it created
     */
    function __construct($filePath)
    {
        $this->filePath = $filePath;
    }

    /**
     * Get IV
     */
    function getIV()
    {
        $iv = file_get_contents($this->filePath);

        if (!$iv) {
            $iv = mcrypt_create_iv(mcrypt_get_iv_size(Crypt::CIPHER, Crypt::MODE), MCRYPT_RAND);

            if (!is_writable($this->filePath))
                throw new \InvalidArgumentException(sprintf(
                    '(%s) Must be writable.'
                    , \Poirot\Std\flatten($this->filePath)
                ));

            file_put_contents($this->filePath, $iv);
        }

        return $iv;
    }

    
    // ..

    function __toString()
    {
        $iv = '';

        try{
            $iv = $this->getIV();
        } catch (\Exception $e) {

        }

        return $iv;
    }
}