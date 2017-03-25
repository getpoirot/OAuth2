<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoRefreshTokens
{
    /**
     * Insert New Token
     *
     * @param iEntityRefreshToken $token
     *
     * @return iEntityAccessToken include insert id
     */
    function insert(iEntityRefreshToken $token);

    /**
     * Find Token Match By Identifier
     *
     * note: it must not gather tokens that expired by time
     * 
     * @param string $tokenIdentifier
     * 
     * @return iEntityRefreshToken|false
     */
    function findByIdentifier($tokenIdentifier);
    
    /**
     * Remove Token From Persistence
     * used to revoke token!
     * 
     * @param string $tokenIdentifier
     * 
     * @return int
     */
    function removeByIdentifier($tokenIdentifier);
    
}
