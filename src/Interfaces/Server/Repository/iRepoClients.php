<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoClients
{
    /**
     * Insert New Client
     *
     * @param iOAuthClient $client
     *
     * @return iOAuthClient include insert id
     * @throws \Exception
     */
    function insert(iOAuthClient $client);

    /**
     * Find Client By Identifier
     * 
     * @param string|int $clientID
     *
     * @return iOAuthClient|false
     */
    function findByIdentifier($clientID);

    /**
     * Find Client By Combination Of ID/Secret
     *
     * ! clients must be authenticated by which method contract
     *   between client and server.
     *   by which id/secret validation is default.
     *
     * @param string|int $clientID
     * @param string     $secretKey
     *
     * @return iOAuthClient|false
     */
    function findByIDSecretKey($clientID, $secretKey);
}
