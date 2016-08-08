<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoUser
{
    /**
     * Find User By Identifier
     *
     * @param string|int $userID
     *
     * @return iEntityUser|false
     */
    function findByIdentifier($userID);

    /**
     * Find User By Combination Of Username/Password (identifier/credential)
     *
     * @param string|int $username
     * @param string     $password
     *
     * @return iEntityUser|false
     */
    function findByUserPass($username, $password);
    
}
