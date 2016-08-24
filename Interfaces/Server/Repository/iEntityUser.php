<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iEntityUser
{
    /**
     * Unique User Identifier (username) 
     *
     * @return string|int
     */
    function getIdentifier();

    /**
     * Get Credential
     * 
     * @return string
     */
    function getCredential();
    
}
