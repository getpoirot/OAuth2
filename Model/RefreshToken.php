<?php
namespace Poirot\OAuth2\Model;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;

class RefreshToken 
    extends AccessToken
    implements iEntityRefreshToken
{
    /** @var string|int */
    protected $identifier;
    /** @var iEntityAccessToken */
    protected $accessToken;


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
        if (! (is_int($identifier) || is_string($identifier)) )
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
     * @return iEntityAccessToken
     */
    function getAccessTokenIdentifier()
    {
        return $this->accessToken;
    }

    /**
     * @param iEntityAccessToken $accessToken
     * 
     * @return $this
     */
    function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;
        return $this;
    }

}
