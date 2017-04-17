<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoUsers
{
    /**
     * Find User By Identifier (username)
     *
     * @param string $uid
     *
     * @return iOAuthUser|false
     */
    function findOneByUID($uid);

    /**
     * Find User By Combination Of Username/Password (identifier/credential)
     *
     * !! Method Mandatory to Implement "password" Grant
     *
     * @param string $username
     * @param string $credential
     *
     * @return iOAuthUser|false
     */
    function findOneByUserPass($username, $credential);
    
}
