<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoUser
{
    /**
     * Find User By Identifier
     *
     * @param string|int $identifier
     *
     * @return iEntityUser|false
     */
    function findByIdentifier($identifier);

    /**
     * Find User By Combination Of Username/Password (identifier/credential)
     *
     * @param string|int $identifier
     * @param string     $credential
     *
     * @return iEntityUser|false
     */
    function findByUserCredential($identifier, $credential);
    
}
