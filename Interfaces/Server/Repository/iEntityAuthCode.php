<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

/**
 * - Authorization Code Can Be Stateless
 */

interface iEntityAuthCode
{
    /**
     * Unique Token Identifier
     *
     * @return string|int
     */
    function getIdentifier();

    /**
     * Client Identifier That Token Issued To
     *
     * @return string|int
     */
    function getClientIdentifier();

    /**
     * Get the token's expiry date time
     *
     * @return \DateTime
     */
    function getExpiryDateTime();

    /**
     * Return an array of scopes associated with the token
     *
     * @return string[]
     */
    function getScopes();

    /**
     * Resource Owner Of Token
     *
     * @return string|int|null
     */
    function getOwnerIdentifier();

    /**
     * Redirect Uri That Auth Code Generated For
     * 
     * @return string
     */
    function getRedirectUri();

    /**
     * @return string
     */
    function getCodeChallenge();
    
    /**
     * @return string
     */
    function getCodeChallengeMethod();
}
