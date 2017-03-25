<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;

abstract class aGrantResponseAccessToken
    extends aGrantResponse
{
    /** @var iEntityAccessToken */
    protected $accessToken;
    protected $refreshToken;

    
    /**
     * Get Access Token
     * 
     * @return iEntityAccessToken
     */
    function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Set Access Token
     * 
     * @param iEntityAccessToken $accessToken
     * 
     * @return $this
     */
    function setAccessToken(iEntityAccessToken $accessToken)
    {
        $this->accessToken = $accessToken;
        return $this;
    }

    /**
     * Get Refresh Token Issued To Access Token
     *
     * - access token
     *
     * @return |null
     */
    function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Set Refresh Token Issued To This Token
     *
     * @param mixed $refreshToken
     *
     * @return $this
     */
    function setRefreshToken($refreshToken)
    {
        $this->refreshToken = $refreshToken;
        return $this;
    }
}
