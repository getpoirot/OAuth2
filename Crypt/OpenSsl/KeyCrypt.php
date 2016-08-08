<?php
namespace Poirot\OAuth2\Crypt\OpenSsl;

class KeyCrypt
{
    /** @var string */
    protected $keyPath;
    /** @var null|string */
    protected $passPhrase;

    /**
     * RsaKey constructor.
     * 
     * @param string      $keyPath
     * @param string|null $passPhrase
     */
    function __construct($keyPath, $passPhrase = null)
    {
        if (strpos($keyPath, 'file://') !== 0)
            $keyPath = 'file://' . $keyPath;

        if (!file_exists($keyPath) || !is_readable($keyPath))
            throw new \LogicException(sprintf('Key path "%s" does not exist or is not readable', $keyPath));

        $this->keyPath = $keyPath;
        $this->passPhrase = $passPhrase;
    }

    /**
     * Retrieve key path.
     *
     * @return string
     */
    function getKeyPath()
    {
        return $this->keyPath;
    }

    /**
     * Retrieve key pass phrase.
     *
     * @return null|string
     */
    function getPassPhrase()
    {
        return $this->passPhrase;
    }
}
