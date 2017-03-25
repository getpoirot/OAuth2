<?php
namespace Poirot\OAuth2\Model;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;


class RefreshToken 
    extends AccessToken
    implements iEntityRefreshToken
{
    /** @var string|int */
    protected $identifier;
    protected $accessTokenIdentifier;


    /**
     * Unique Token Identifier
     *
     * @return string|int
     */
    function getIdentifier()
    {
        if (!$this->identifier)
            // generate token if it not provided!
            $this->setIdentifier(\Poirot\OAuth2\generateUniqueIdentifier());
        
        return $this->identifier;
    }

    /**
     * @param int|string $identifier
     * 
     * @return $this
     */
    function setIdentifier($identifier)
    {
        if ($identifier !== null && ! (is_int($identifier) || is_string($identifier)) )
            throw new \InvalidArgumentException(sprintf(
                'Identifier must be int or string; given: (%s).'
                , \Poirot\Std\flatten($identifier)
            ));
        
        $this->identifier = $identifier;
        return $this;
    }

    /**
     * Get Access Token That Token Issued To
     *
     * @return string
     */
    function getAccessTokenIdentifier()
    {
        return $this->accessTokenIdentifier;
    }

    /**
     * @param string $identifier
     * @return $this
     */
    function setAccessTokenIdentifier($identifier)
    {
        if ($identifier !== null && ! (is_int($identifier) || is_string($identifier)) )
            throw new \InvalidArgumentException(sprintf(
                'Identifier must be int or string; given: (%s).'
                , \Poirot\Std\flatten($identifier)
            ));
        
        $this->accessTokenIdentifier = (string) $identifier;
        return $this;
    }
}
