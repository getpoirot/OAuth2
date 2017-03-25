<?php
namespace Poirot\OAuth2\Model\Repo\Stateless;

use Poirot\OAuth2\Interfaces\iEncrypt;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAuthCode;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoAuthCodes;
use Poirot\OAuth2\Model\AuthCode;


class AuthorizationCodes
    implements iRepoAuthCodes
{
    /** @var iEncrypt */
    protected $encryption;


    /**
     * AccessTokens constructor.
     *
     * @param iEncrypt $encryption
     */
    function __construct(iEncrypt $encryption)
    {
        $this->encryption = $encryption;
    }

    /**
     * Persist New Authorization Code
     *
     * @param iEntityAuthCode $token
     *
     * @return iEntityAuthCode include insert id
     */
    function insert(iEntityAuthCode $token)
    {
        $tokenData = array(
            ## this identifier give back when unserialize token
            #- it can be the used as id on other persistence
            'identifier'              => $token->getIdentifier(), 
            'client_identifier'       => $token->getClientIdentifier(),
            'expiry_date_time'        => $token->getExpiryDateTime(),
            'scopes'                  => $token->getScopes(),
            'owner_identifier'        => $token->getOwnerIdentifier(),
            'redirect_uri'            => $token->getRedirectUri(),
            'code_challenge'          => $token->getCodeChallenge(),
            'code_challenge_method'   => $token->getCodeChallengeMethod(),
        );

        // Identifier will give back to user as token
        $identifier = serialize($tokenData);
        $identifier = $this->encryption->encrypt($identifier);

        $newToken = new AuthCode($tokenData);
        $newToken->setIdentifier($identifier);
        return $newToken;
    }

    /**
     * Find Code Match By Identifier
     *
     * @param string $identifier
     *
     * @return iEntityAuthCode|false
     */
    function findByIdentifier($identifier)
    {
        $tokenData = $this->encryption->decrypt($identifier);
        $tokenData = unserialize($tokenData);

        $token = new AuthCode($tokenData);
        $token->setIdentifier($identifier); // replace identifier to stateless one
        return $token;
    }

    /**
     * Remove Token From Persistence
     * used to revoke token!
     *
     * @param string $tokenIdentifier
     *
     * @return void
     */
    function removeByIdentifier($tokenIdentifier)
    {
        // Stateless Authorization Code Revoke Not Implemented!
        // ..

    }
}
