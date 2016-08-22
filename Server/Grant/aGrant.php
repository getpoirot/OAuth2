<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\iGrant;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityClient;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityUser;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoClient;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoAccessToken;
use Poirot\OAuth2\Model\AccessToken;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidClient;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;

use Poirot\OAuth2\Server\Response\aGrantResponse;

use Poirot\Std\ConfigurableSetter;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class aGrant 
    extends ConfigurableSetter
    implements iGrant
{
    /** @var iRepoClient */
    protected $repoClient;
    /** @var iRepoAccessToken */
    protected $repoAccessToken;
    
    
    /** @var \DateInterval */
    protected $ttlAccessToken;
    

    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    abstract function getGrantType();
    
    /**
     * Respond To Grant Request
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exInvalidRequest|exOAuthServer
     */
    abstract function respond(ServerRequestInterface $request, ResponseInterface $response);
    
    /**
     * New Grant Response
     *
     * @return aGrantResponse
     */
    abstract function newGrantResponse();

    /**
     * Can This Grant Respond To Request
     *
     * - usually it match against "grant_type" request
     *
     * @param ServerRequestInterface $request
     *
     * @return boolean
     */
    function canRespondToRequest(ServerRequestInterface $request)
    {
        $requestParameters = (array) $request->getParsedBody();
        
        return (
            array_key_exists('grant_type', $requestParameters)
            && $requestParameters['grant_type'] === $this->getGrantType()
        );
    }
    
    
    // Utils:

    /**
     * Attain and validate Client Credential/ID by Request
     * 
     * - check redirect uri match by pre-registered value
     *
     * @param ServerRequestInterface $request
     * @param bool                   $validateSecretKey Client is confidential 
     * 
     * @return iEntityClient
     * @throws exInvalidRequest|exInvalidClient
     */
    protected function assertClient(ServerRequestInterface $request, $validateSecretKey = true)
    {
        if (false === $AuthClient = \Poirot\OAuth2\parseClientIdSecret($request))
            throw new exInvalidRequest;

        if ($validateSecretKey)
            $client = $this->repoClient->findByIDSecretKey($AuthClient->clientId, $AuthClient->secretKey);
        else 
            $client = $this->repoClient->findByIdentifier($AuthClient->clientId);

        if (!$client instanceof iEntityClient)
            throw new exInvalidClient;

        // If a redirect URI is provided ensure it matches what is pre-registered

        // maybe redirect_uri find in request query params
        // used in authorization grants like implicit ..
        $reqParams         = $request->getQueryParams();
        $redirectUri       = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri']);

        $reqParams         = (array) $request->getParsedBody();
        $redirectUri       = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri'], $redirectUri);
        if ( $redirectUri !== null && ! in_array($redirectUri, $client->getRedirectUri()) )
            ## redirect-uri not match 
            throw new exInvalidClient;

        return $client;
    }

    /**
     * Assert Requested Scopes And Reduce Or Append Scope
     * 
     * ! requested scope must equal or narrow to client/refreshToken pre-registered scopes
     * 
     * @param ServerRequestInterface $request
     * @param array                  $preScopes iClientEntity->getScopes(), ...
     * 
     * @return array [ scopeRequested => string[], scopeGranted => string[] ]
     */
    protected function assertScopes(ServerRequestInterface $request, array $preScopes)
    {
        // maybe scope find in request query params
        // used in authorization grants like implicit ..
        $reqParams  = $request->getQueryParams();
        $scopes     = \Poirot\Std\emptyCoalesce(@$reqParams['scope']);
        
        $reqParams = (array) $request->getParsedBody();
        $scopes    = \Poirot\Std\emptyCoalesce(@$reqParams['scope'], $scopes);
        if (!empty($scopes))
            $scopes = explode(' ' /* Scope Delimiter */, trim($scopes));
        else
            $scopes = array();
        
        if (empty($scopes)) {
            $scopes = $preScopes;
            $scopeGranted = $scopes;
        }
        else
            $scopeGranted = array_filter(
                $scopes
                , function ($scope) use ($preScopes) {
                // Scopes Not Pre-Registered To Client Will Excluded!!
                // (!) we must back scope to client if it differ 
                return in_array($scope, $preScopes);
            });
        
        return array('scopeRequested' => $scopes, 'scopeGranted' => $scopeGranted, 0 => $scopes, 1 => $scopeGranted);
    }

    
    /**
     * Issue Token and Persist It
     * 
     * @param iEntityClient $client
     * @param \DateInterval $accessTokenTTL
     * @param array         $scopes
     * @param iEntityUser   $resourceOwner
     * 
     * @return iEntityAccessToken
     */
    protected function issueAccessToken(iEntityClient $client
        , \DateInterval $accessTokenTTL
        , iEntityUser $resourceOwner = null
        , $scopes = array()
    ) {
        $token = new AccessToken();
        $token->setScopes($scopes);
        $token->setClientIdentifier($client->getIdentifier());
        $curTime = new \DateTime();
        $token->setExpiryDateTime($curTime->add($accessTokenTTL));
        if ($resourceOwner) $token->setOwnerIdentifier($resourceOwner->getIdentifier());

        $iToken = $this->repoAccessToken->insert($token);
        return $iToken;
    }

    
    // Options:
    
    /**
     * Set Access Token Time To Live
     * 
     * @param \DateInterval $dateInterval
     * 
     * @return $this
     */
    function setTtlAccessToken(\DateInterval $dateInterval)
    {
        $this->ttlAccessToken = $dateInterval;
        return $this;
    }

    /**
     * Get Access Token Time To Live
     * 
     * @return \DateInterval
     */
    function getTtlAccessToken()
    {
        if (!$this->ttlAccessToken)
            $this->setTtlAccessToken(new \DateInterval('PT1H'));
        
        return $this->ttlAccessToken;
    }
    
    
    function setRepoClient(iRepoClient $repoClient)
    {
        $this->repoClient = $repoClient;
        return $this;
    }

    function setRepoAccessToken(iRepoAccessToken $repoAccessToken)
    {
        $this->repoAccessToken = $repoAccessToken;
        return $this;
    }
}
