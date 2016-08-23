<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Model\RefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityUser;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoUser;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidCredential;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\aGrantResponseAccessToken;
use Poirot\OAuth2\Server\Response\GrantResponseBearerToken;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


class GrantPassword
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
        return 'password';
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
        $client = $this->assertClient($request, true);
        list($scopeRequested, $scopes) = $this->assertScopes($request, $client->getScope());

        $user   = $this->assertUser($request);

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
     * Attain User by Request
     *
     * @param ServerRequestInterface $request
     * 
     * @return iEntityUser
     * @throws exInvalidCredential|exInvalidRequest
     */
    protected function assertUser(ServerRequestInterface $request)
    {
        $requestParameters = (array) $request->getParsedBody();
        $username = \Poirot\Std\emptyCoalesce(@$requestParameters['username']);
        $password = \Poirot\Std\emptyCoalesce(@$requestParameters['password']);
        
        if (is_null($username) || is_null($password))
            // 
            throw new exInvalidRequest;

        $user = $this->repoUser->findByUserCredential($username, $password);
        if (!$user instanceof iEntityUser)
            // TODO
            throw new exInvalidCredential;

        return $user;
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
