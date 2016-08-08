<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoAuthCode
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
     * @param string $authCodeIdentifier
     *
     * @return iEntityAuthCode|false
     */
    function findByIdentifier($authCodeIdentifier);
}
