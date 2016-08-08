<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

/**
 * - Refresh Token Can Be Stateless
 */

interface iEntityRefreshToken 
    extends iEntityAccessToken
{
    /**
     * Unique Token Identifier
     *
     * @return string|int
     */
    function getIdentifier();

    /**
     * Get Access Token Identifier That Token Issued To
     * 
     * @return string|int
     */
    function getAccessTokenIdentifier();
}
