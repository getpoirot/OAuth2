<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Model\RefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iOAuthClient;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshTokens;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoUsers;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\aGrantResponseAccessToken;
use Poirot\OAuth2\Server\Response\GrantResponseJson;

use Psr\Http\Message\ResponseInterface;


class GrantRefreshToken
    extends aGrant
{
    /** @var iRepoRefreshTokens */
    protected $repoRefreshToken;
    /** @var iRepoUsers */
    protected $repoUser;

    /** @var \DateInterval */
    protected $ttlRefreshToken;
    
    
    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    function getGrantType()
    {
        return 'refresh_token';
    }
    
    /**
     * Respond To Grant Request
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    function respond(ResponseInterface $response)
    {
        $client          = $this->assertClient(true);
        $oldRefreshToken = $this->assertRefreshToken($client);

        list($scopeRequested, $scopes) =  $this->assertScopes($oldRefreshToken->getScopes());
        
        # Expire old tokens
        $this->repoAccessToken->removeByIdentifier($oldRefreshToken->getAccessTokenIdentifier());
        $this->repoRefreshToken->removeByIdentifier($oldRefreshToken->getIdentifier());

        # Issue New Tokens
        $user          = $this->repoUser->findOneByUID($oldRefreshToken->getOwnerIdentifier());
        if (! $user )
            throw exOAuthServer::invalidRefreshToken(sprintf(
                'User (%s) is not found.', $oldRefreshToken->getOwnerIdentifier())
                , $this->newGrantResponse()
            );
        
        $accToken      = $this->issueAccessToken($client, $this->getTtlAccessToken(), $user, $scopes);
        $refToken      = $this->issueRefreshToken($accToken, $this->getTtlRefreshToken());
        
        $grantResponse = $this->newGrantResponse();
        $grantResponse->setAccessToken($accToken);
        $grantResponse->setRefreshToken($refToken);
        if (array_diff($scopeRequested, $scopes))
            // the issued access token scope is different from the
            // one requested by the client, include the "scope"
            // response parameter to inform the client of the
            // actual scope granted.
            $grantResponse->import(array(
                'scope' => implode(' ' /* Scope Delimiter */, $scopes),
            ));

        $response = $grantResponse->toResponseWith($response);
        return $response;
    }
    
    /**
     * New Grant Response
     *
     * @return GrantResponseJson|aGrantResponseAccessToken
     */
    function newGrantResponse()
    {
        return new GrantResponseJson();
    }
    
    
    // ...

    /**
     * @param iOAuthClient $client
     *
     * @return iEntityRefreshToken
     * @throws exOAuthServer
     */
    protected function assertRefreshToken(iOAuthClient $client)
    {
        $request = $this->request;
        
        $requestParameters      = (array) $request->getParsedBody();
        $refreshTokenIdentifier = $requestParameters['refresh_token'] ?? null;
        if (!$refreshTokenIdentifier)
            throw exOAuthServer::invalidRequest('refresh_token', null, $this->newGrantResponse());

        $refreshToken = $this->repoRefreshToken->findByIdentifier($refreshTokenIdentifier);

        if (!$refreshToken instanceof iEntityRefreshToken)
            // Token is Revoked!!
            throw exOAuthServer::invalidRefreshToken('Refresh Token is Revoked', $this->newGrantResponse());

        if ($refreshToken->getClientIdentifier() !== $client->getIdentifier())
            throw exOAuthServer::invalidRefreshToken(null, $this->newGrantResponse());

        if ($refreshToken->getDateTimeExpiration()->getTimestamp() < time())
            throw exOAuthServer::invalidRefreshToken('Refresh Token Is Expired', $this->newGrantResponse());

        return $refreshToken;
    }

    /**
     * Issue Refresh Token To Access Token and Persist It
     *
     * @param iEntityAccessToken $accessToken
     * @param \DateInterval      $refreshTokenTTL
     *
     * @return iEntityRefreshToken
     */
    protected function issueRefreshToken(iEntityAccessToken $accessToken, \DateInterval $refreshTokenTTL)
    {
        // refresh token have same data as access token
        $curTime = new \DateTime();
        $token   = new RefreshToken;
        $token
            ->setAccessTokenIdentifier($accessToken->getIdentifier())
            ->setClientIdentifier($accessToken->getClientIdentifier())
            ->setScopes($accessToken->getScopes())
            ->setOwnerIdentifier($accessToken->getOwnerIdentifier())
            ->setDateTimeExpiration($curTime->add($refreshTokenTTL))
        ;

        $iToken = $this->repoRefreshToken->insert($token);
        return $iToken;
    }
    
    
    // Options:

    /**
     * Set Refresh Token Time To Live
     *
     * @param \DateInterval $dateInterval
     *
     * @return $this
     */
    function setTtlRefreshToken(\DateInterval $dateInterval)
    {
        $this->ttlRefreshToken = $dateInterval;
        return $this;
    }

    /**
     * Get Refresh Token Time To Live
     *
     * @return \DateInterval
     */
    function getTtlRefreshToken()
    {
        if (!$this->ttlRefreshToken)
            $this->setTtlRefreshToken(new \DateInterval('P1M'));

        return $this->ttlRefreshToken;
    }
    
    
    function setRepoUser(iRepoUsers $repoUser)
    {
        $this->repoUser = $repoUser;
        return $this;
    }

    function setRepoRefreshToken(iRepoRefreshTokens $repoRefreshToken)
    {
        $this->repoRefreshToken = $repoRefreshToken;
        return $this;
    }
}
