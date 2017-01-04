<?php
namespace Poirot\OAuth2\Model\Repo\Stateless;

use Poirot\OAuth2\Interfaces\iEncrypt;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshTokens;


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
        $persistToken = new RefreshToken;
        $persistToken
            ## this identifier give back when token unserialized
            #- it can be the used as id on other persistence
            ->setIdentifier($token->getIdentifier())
            ->setClientIdentifier($token->getClientIdentifier())
            ->setDateTimeExpiration($token->getDateTimeExpiration())
            ->setScopes($token->getScopes())
            ->setOwnerIdentifier($token->getOwnerIdentifier())
            ->setAccessTokenIdentifier($token->getAccessTokenIdentifier())
        ;

        // Identifier will give back to user as token
        $identifier = serialize($persistToken);
        $identifier = $this->encryption->encrypt($identifier);

        $persistToken->setIdentifier($identifier);
        return $persistToken;
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
        $tokenEncrypted = $this->encryption->decrypt($tokenIdentifier);
        if (false === $token = @unserialize($tokenEncrypted))
            throw new \Exception('Error Retrieve Refresh Token; Parse Error!!!');

        /** @var RefreshToken $token */

        # check expire time
        if (\Poirot\OAuth2\checkExpiry($token->getDateTimeExpiration()))
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
