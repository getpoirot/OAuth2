<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Model\RefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityClient;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityUser;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoUser;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidRefreshToken;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\aGrantResponseAccessToken;
use Poirot\OAuth2\Server\Response\GrantResponseBearerToken;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class GrantRefreshToken
    extends aGrant
{
    /** @var iRepoRefreshToken */
    protected $repoRefreshToken;
    /** @var iRepoUser */
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
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exInvalidRequest|exOAuthServer
     */
    function respond(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client          = $this->assertClient($request, true);
        $oldRefreshToken = $this->assertRefreshToken($request, $client);

        list($scopeRequested, $scopes) =  $this->assertScopes($request, $oldRefreshToken->getScopes());
        
        # Expire old tokens
        $this->repoAccessToken->removeByIdentifier($oldRefreshToken->getAccessTokenIdentifier());
        $this->repoRefreshToken->removeByIdentifier($oldRefreshToken->getIdentifier());

        # Issue New Tokens
        $user          = $this->repoUser->findByIdentifier($oldRefreshToken->getOwnerIdentifier());
        if (!$user)
            // TODO
            throw new exInvalidRefreshToken;
        
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
            $grantResponse->setExtraParams(array(
                'scope' => implode(' ' /* Scope Delimiter */, $scopes),
            ));

        $response = $grantResponse->buildResponse($response);
        return $response;
    }
    
    /**
     * New Grant Response
     *
     * @return GrantResponseBearerToken|aGrantResponseAccessToken
     */
    function newGrantResponse()
    {
        return new GrantResponseBearerToken();
    }
    
    
    // ...

    /**
     * @param ServerRequestInterface $request
     * @param iEntityClient $client
     *
     * @return iEntityRefreshToken
     * @throws exInvalidRequest|exInvalidRefreshToken
     */
    protected function assertRefreshToken(ServerRequestInterface $request, iEntityClient $client)
    {
        $requestParameters      = (array) $request->getParsedBody();
        $refreshTokenIdentifier = \Poirot\Std\emptyCoalesce(@$requestParameters['refresh_token']);
        if (!$refreshTokenIdentifier)
            // TODO
            throw new exInvalidRequest;

        $refreshToken = $this->repoRefreshToken->findByIdentifier($refreshTokenIdentifier);

        if (!$refreshToken instanceof iEntityRefreshToken)
            // Token is Revoked!! TODO
            throw new exInvalidRefreshToken;

        if ($refreshToken->getClientIdentifier() !== $client->getIdentifier())
            // TODO
            throw new exInvalidRefreshToken;

        if ($refreshToken->getExpiryDateTime()->getTimestamp() < time())
            // TODO
            throw new exInvalidRefreshToken;

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
        $token   = new RefreshToken();
        $token
            ->setAccessTokenIdentifier($accessToken->getIdentifier())
            ->setClientIdentifier($accessToken->getClientIdentifier())
            ->setScopes($accessToken->getScopes())
            ->setOwnerIdentifier($accessToken->getOwnerIdentifier())
            ->setExpiryDateTime($curTime->add($refreshTokenTTL))
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
    
    
    function setRepoUser(iRepoUser $repoUser)
    {
        $this->repoUser = $repoUser;
        return $this;
    }

    function setRepoRefreshToken(iRepoRefreshToken $repoRefreshToken)
    {
        $this->repoRefreshToken = $repoRefreshToken;
        return $this;
    }
}
