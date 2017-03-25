<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\iGrant;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityClient;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityUser;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoClients;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoAccessTokens;
use Poirot\OAuth2\Model\AccessToken;

use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\aGrantResponse;

use Poirot\Std\ConfigurableSetter;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


abstract class aGrant 
    extends ConfigurableSetter
    implements iGrant
{
    /** @var iRepoClients */
    protected $repoClient;
    /** @var iRepoAccessTokens */
    protected $repoAccessToken;
    
    /** @var \DateInterval */
    protected $ttlAccessToken;
    
    
    /** @var ServerRequestInterface Prepared request object from canRespond */
    protected $request;
    
    protected $_c_assert_client;
    protected $_c_assert_scopes;


    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    abstract function getGrantType();

    /**
     * Respond To Grant Request
     *
     * @param ResponseInterface  $response
     * 
     * @return ResponseInterface prepared response
     */
    abstract function respond(ResponseInterface $response);
    
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
        
        $return = false;
        
        if (
            array_key_exists('grant_type', $requestParameters)
            && $requestParameters['grant_type'] === $this->getGrantType()
        ) {
            $return = clone $this;
            $return->request = $request;
        }
        
        return $return;
    }

    /**
     * New Grant Response
     *
     * @return aGrantResponse
     */
    abstract function newGrantResponse();
    
    
    // Utils:

    /**
     * Attain and validate Client Credential/ID by Request
     *
     * - check redirect uri match by pre-registered value
     *
     * @param bool $validateSecretKey Client is confidential
     * 
     * @return iEntityClient
     * @throws exOAuthServer
     */
    function assertClient($validateSecretKey = true)
    {
        if ($this->_c_assert_client)
            return $this->_c_assert_client;
        
        
        $request = $this->request;
        if (false === $AuthClient = \Poirot\OAuth2\parseClientIdSecret($request))
            throw exOAuthServer::invalidRequest('client_id', null, $this->newGrantResponse());

        try {
            if ($validateSecretKey)
                $client = $this->repoClient->findByIDSecretKey($AuthClient->clientId, $AuthClient->secretKey);
            else
                $client = $this->repoClient->findByIdentifier($AuthClient->clientId);
        } catch (\Exception $e) {
            throw exOAuthServer::serverError('Server Client Database has rise an error.', $this->newGrantResponse());
        }

        if (!$client instanceof iEntityClient)
            // So we must not redirect back the error result to client
            // responder as an argument are abandoned!!
            throw exOAuthServer::invalidClient();

        $this->_c_assert_client = $client;


        // If a redirect URI is provided ensure it matches what is pre-registered

        // maybe redirect_uri find in request query params
        // used in authorization grants like implicit ..
        $reqParams         = $request->getQueryParams();
        $redirectUri       = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri']);

        $reqParams         = (array) $request->getParsedBody();
        $redirectUri       = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri'], $redirectUri);
        if ($redirectUri !== null) {
            $redirectUri = rtrim($redirectUri, '/');
            $match = false;
            foreach ($client->getRedirectUri() as $registeredRedirect) {
                $registeredRedirect = rtrim($registeredRedirect, '/');
                if ($redirectUri == $registeredRedirect) {
                    $match = true;
                    break;
                }
            }

            if ( !$match )
                ## redirect-uri not match
                throw exOAuthServer::invalidClient($this->newGrantResponse());
        }

        return $client;
    }

    /**
     * Assert Requested Scopes And Reduce Or Append Scope
     * 
     * ! requested scope must equal or narrow to client/refreshToken pre-registered scopes
     * 
     * @param array                  $defaultScopes iClientEntity->getScopes(), ...
     * 
     * @return array [ scopeRequested => string[], scopeGranted => string[] ]
     */
    function assertScopes(array $defaultScopes)
    {
        if ($this->_c_assert_scopes)
            return $this->_c_assert_scopes;
        
        $request = $this->request;
        
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
            $scopes       = $defaultScopes;
            $scopeGranted = $scopes;
        }
        else {
            $scopeGranted = array_filter(
                $scopes
                , function ($scope) use ($defaultScopes) {
                // Scopes Not Pre-Registered To Client Will Excluded!!
                // (!) we must back scope to client if it differ
                return in_array($scope, $defaultScopes);
            });

            if (empty($scopeGranted))
                // Invalid Scopes
                throw exOAuthServer::invalidRequest('scope', null, $this->newGrantResponse());
        }

        return $this->_c_assert_scopes = array(
              'scopeRequested' => $scopes
            , 'scopeGranted' => $scopeGranted
            , 0 => $scopes
            , 1 => $scopeGranted
        );
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
        $exprDateTime = __( new \DateTime())->add($accessTokenTTL);
        $token = new AccessToken;
        $token
            ->setScopes($scopes)
            ->setClientIdentifier($client->getIdentifier())
            ->setDateTimeExpiration($exprDateTime)
        ;

        if ($resourceOwner) $token->setOwnerIdentifier($resourceOwner->getUID());

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
    
    
    function setRepoClient(iRepoClients $repoClient)
    {
        $this->repoClient = $repoClient;
        return $this;
    }

    function setRepoAccessToken(iRepoAccessTokens $repoAccessToken)
    {
        $this->repoAccessToken = $repoAccessToken;
        return $this;
    }
}
