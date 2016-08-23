<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoUser
{
    /**
     * Find User By Identifier (username)
     *
     * @param string $identifier
     *
     * @return iEntityUser|false
     */
    function findByIdentifier($identifier);

    /**
     * Find User By Combination Of Username/Password (identifier/credential)
     *
     * @param string $identifier
     * @param string $credential
     *
     * @return iEntityUser|false
     */
    function findByUserCredential($identifier, $credential);
    
}
