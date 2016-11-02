<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoAuthCodes
{
    /**
     * Persist New Authorization Code
     *
     * @param iEntityAuthCode $token
     *
     * @return iEntityAuthCode include insert id
     */
    function insert(iEntityAuthCode $token);

    /**
     * Find Code Match By Identifier
     *
     * @param string $identifier
     *
     * @return iEntityAuthCode|false
     */
    function findByIdentifier($identifier);

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
