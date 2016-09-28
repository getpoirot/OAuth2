<?php
namespace Poirot\OAuth2\Model\Repo\Stateless;

use Poirot\OAuth2\Interfaces\iEncrypt;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoAccessToken;
use Poirot\OAuth2\Model\AccessToken;


class AccessTokens
    implements iRepoAccessToken
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
     * Insert New Token
     *
     * @param iEntityAccessToken $token
     *
     * @return iEntityAccessToken include insert id
     */
    function insert(iEntityAccessToken $token)
    {
        $tokenData = array(
            ## this identifier give back when unserialize token
            #- it can be the used as id on other persistence
            'identifier'              => $token->getIdentifier(),
            'client_identifier'       => $token->getClientIdentifier(),
            'expiry_date_time'        => $token->getExpiryDateTime(),
            'scopes'                  => $token->getScopes(),
            'owner_identifier'        => $token->getOwnerIdentifier(),
        );

        // Identifier will give back to user as token
        $identifier = serialize($tokenData);
        $identifier = $this->encryption->encrypt($identifier);

        $newToken = new AccessToken($tokenData);
        $newToken->setIdentifier($identifier);
        return $newToken;
    }

    /**
     * Find Token Match By Identifier
     *
     * note: it must not gather tokens that expired by time
     *
     * @param string $tokenIdentifier
     *
     * @return iEntityAccessToken|false
     */
    function findByIdentifier($tokenIdentifier)
    {
        $tokenData = $this->encryption->decrypt($tokenIdentifier);
        $tokenData = unserialize($tokenData);

        $token = new AccessToken($tokenData);
        
        # check expire time 
        if (\Poirot\OAuth2\checkExpiry($token->getExpiryDateTime()))
            return false;
        
        $token->setIdentifier($tokenIdentifier); // replace identifier to stateless one
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
        // Stateless Access Tokens Revoke Not Implemented!
        // ..

    }
}
