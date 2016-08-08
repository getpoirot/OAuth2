<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoAccessToken
{
    /**
     * Insert New Token
     *
     * @param iEntityAccessToken $token
     *
     * @return iEntityAccessToken include insert id
     */
    function insert(iEntityAccessToken $token);

    /**
     * Find Token Match By Identifier
     * 
     * @param string $tokenIdentifier
     * 
     * @return iEntityAccessToken|false
     */
    function findByIdentifier($tokenIdentifier);
    
    /**
     * Remove Token From Persistence
     * used to revoke token!
     * 
     * @param string $tokenIdentifier
     * 
     * @return void
     */
    function removeByIdentifier($tokenIdentifier);
    
}
