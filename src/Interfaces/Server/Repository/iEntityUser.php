<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iEntityUser
{
    /**
     * Unique User Identifier
     *
     * !! Identifier Must Be Unique
     *
     * @return string|int
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
