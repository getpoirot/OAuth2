<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iRepoClient
{
    /**
     * Insert New Client
     *
     * @param iEntityClient $client
     *
     * @return iEntityClient include insert id
     * @throws \Exception
     */
    function insert(iEntityClient $client);

    /**
     * Find Client By Identifier
     * 
     * @param string|int $clientID
     *
     * @return iEntityClient|false
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
     * @return iEntityClient|false
     */
    function findByIDSecretKey($clientID, $secretKey);
}
