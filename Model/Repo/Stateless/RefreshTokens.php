<?php
namespace Poirot\OAuth2\Model\Repo\Stateless;

use Poirot\OAuth2\Interfaces\iEncrypt;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshTokens;
use Poirot\OAuth2\Model\RefreshToken;


class RefreshTokens
    implements iRepoRefreshTokens
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
     * @param iEntityRefreshToken $token
     *
     * @return iEntityAccessToken include insert id
     */
    function insert(iEntityRefreshToken $token)
    {
        // TODO RefreshToken Stateless Repo with serializable refresh token to map fields
        $tokenData = array(
            ## this identifier give back when unserialize token
            #- it can be the used as id on other persistence
            'identifier'              => $token->getIdentifier(), 
            'access_token_identifier' => $token->getAccessTokenIdentifier(),
            'client_identifier'       => $token->getClientIdentifier(),
            'expiry_date_time'        => $token->getExpiryDateTime(),
            'scopes'                  => $token->getScopes(),
            'owner_identifier'        => $token->getOwnerIdentifier(),
        );

        // Identifier will give back to user as token
        $identifier = serialize($tokenData);
        $identifier = $this->encryption->encrypt($identifier);

        $newToken = new RefreshToken($tokenData);
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
     * @return false|iEntityRefreshToken
     * @throws \Exception
     */
    function findByIdentifier($tokenIdentifier)
    {
        $tokenData = $this->encryption->decrypt($tokenIdentifier);
        if (false === $tokenData = @unserialize($tokenData))
            throw new \Exception('Error Retrieve Refresh Token; Parse Error!!!');

        $token = new RefreshToken($tokenData);

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
