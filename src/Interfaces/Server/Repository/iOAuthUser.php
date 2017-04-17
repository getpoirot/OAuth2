<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iOAuthUser
{
    /**
     * Unique User Identifier
     *
     * !! Identifier Must Be Unique
     *
     * @return mixed
     */
    function getUID();


    // To Implement Basic Grants

    /**
     * Username Unique
     *
     * @return string
     */
    function getUsername();

    /**
     * Get Password Credential
     *
     * @return string
     */
    function getPassword();
}
