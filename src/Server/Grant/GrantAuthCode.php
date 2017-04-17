<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAuthCode;
use Poirot\OAuth2\Interfaces\Server\Repository\iOAuthClient;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iOAuthUser;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoAuthCodes;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshTokens;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoUsers;
use Poirot\OAuth2\Model\AuthCode;
use Poirot\OAuth2\Model\RefreshToken;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\GrantResponseJson;
use Poirot\OAuth2\Server\Response\GrantResponseRedirect;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


class GrantAuthCode
    extends aGrant
{
    /** @var iRepoRefreshTokens */
    protected $repoRefreshToken;
    /** @var iRepoAuthCodes */
    protected $repoAuthCode;
    /** @var iRepoUsers */
    protected $repoUser;

    /** @var \DateInterval */
    protected $ttlAuthCode;
    /** @var \DateInterval */
    protected $ttlRefreshToken;
    
    /** @var callable */
    protected $retrieveUserCallback;

    protected $enableCodeExchangeProof = false;


    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    function getGrantType()
    {
        return 'authorization_code';
    }

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
        $return = false;
        
        if ($this->_isAuthorizationRequest($request) || $this->_isAccessTokenRequest($request)) {
            $return = clone $this;
            $return->request = $request;
        }
        
        return $return;
    }

    protected function _isAuthorizationRequest(ServerRequestInterface $request)
    {
        $requestParameters = $request->getQueryParams();
        $responseType      = \Poirot\Std\emptyCoalesce(@$requestParameters['response_type']);
        $clientIdentifier  = \Poirot\Std\emptyCoalesce(@$requestParameters['client_id']);

        return ($responseType === 'code' && $clientIdentifier !== null);
    }

    protected function _isAccessTokenRequest(ServerRequestInterface $request)
    {
        return parent::canRespondToRequest($request);
    }


    /**
     * Respond To Grant Request
     *
     * note: We consider that user approved the grant
     *       when respond() called...
     *       otherwise the handle of deny is on behalf of
     *       application structure. maybe you want throw exAccessDenied
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    function respond(ResponseInterface $response)
    {
        $request = $this->request;
        
        if ($this->_isAuthorizationRequest($request))
            return $this->_respondAuthorizationCode($request, $response);
        elseif ($this->_isAccessTokenRequest($request))
            return $this->_respondAccessToken($request, $response);
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    protected function _respondAuthorizationCode(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client = $this->assertClient(false);
        list($scopeRequested, $scopes) = $this->assertScopes($client->getScope());

        // The user approved the client, redirect them back with an authorization code

        $user = $this->getUserEntity();

        $reqParams = $request->getQueryParams();
        $redirect  = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri']);
        $redirect  = \Poirot\Std\emptyCoalesce( $redirect, current($client->getRedirectUri()) );
        $state     = \Poirot\Std\emptyCoalesce(@$reqParams['state']);

        $codeChallenge = null; $codeChallengeMethod = null;
        if ($this->enableCodeExchangeProof) {
            $codeChallenge = \Poirot\Std\emptyCoalesce(@$reqParams['code_challenge']);
            if ($codeChallenge === null)
                throw exOAuthServer::invalidRequest('code_challenge', null,  $this->newGrantResponse());

            $codeChallengeMethod = \Poirot\Std\emptyCoalesce(@$reqParams['code_challenge_method'], 'plain');
            if (!in_array($codeChallengeMethod, array('plain', 'S256')))
                throw exOAuthServer::invalidRequest(
                    'code_challenge_method'
                    , 'Code challenge method must be `plain` or `S256`'
                    , $this->newGrantResponse()
                );
        }


        # Finalize Response Contains Authorization Code

        $authCode = $this->issueAuthCode(
            $client
            , $this->getTtlAuthCode()
            , $user
            , $redirect
            , $scopes
            , $codeChallenge
            , $codeChallengeMethod
        );

        $grantResponse = $this->newGrantResponse();
        $grantResponse->import(array(
            'state' => $state,
            'code'  => $authCode->getIdentifier(),
        ));
        $grantResponse->setRedirectUri($redirect);

        $response = $grantResponse->toResponseWith($response);
        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * 
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    protected function _respondAccessToken(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client = $this->assertClient(true);

        $reqParams = (array) $request->getParsedBody();
        $authCodeIdentifier = \Poirot\Std\emptyCoalesce(@$reqParams['code']);
        if ($authCodeIdentifier === null)
            throw exOAuthServer::invalidRequest('code', null, $this->newGrantResponse());

        $authCode = $this->repoAuthCode->findByIdentifier($authCodeIdentifier);

        if (!$authCode instanceof iEntityAuthCode)
            // Code is Revoked!!
            throw exOAuthServer::invalidRequest('code', 'Authorization code has been revoked', $this->newGrantResponse());

        if ($authCode->getClientIdentifier() !== $client->getIdentifier())
            // Authorization code was not issued to this client
            throw exOAuthServer::invalidRequest('code', 'Authorization code is invalid', $this->newGrantResponse());

        if ($authCode->getExpiryDateTime()->getTimestamp() < time())
            // Authorization code has expired
            throw exOAuthServer::invalidRequest('code', 'Authorization code has expired', $this->newGrantResponse());

        $redirectUri = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri']);
        if ($authCode->getRedirectUri() !== $redirectUri)
            // Invalid redirect URI
            throw exOAuthServer::invalidRequest('redirect_uri', null, $this->newGrantResponse());


        list($scopeRequested, $scopes) = $this->assertScopes($authCode->getScopes());


        ## Validate code challenge
        
        if ($this->enableCodeExchangeProof === true) {
            $codeVerifier = \Poirot\Std\emptyCoalesce(@$reqParams['code_verifier']);
            if ($codeVerifier === null)
                throw exOAuthServer::invalidRequest('code_verifier', null, $this->newGrantResponse());

            switch ($authCode->getCodeChallengeMethod()) {
                case 'plain':
                    if (hash_equals($codeVerifier, $authCode->getCodeChallenge()) === false)
                        // InvalidGrant, Failed to verify `code_verifier`.
                        throw exOAuthServer::invalidGrant('Failed to verify `code_verifier`.', $this->newGrantResponse());
                    break;
                case 'S256':
                    if (
                        hash_equals(
                            urlencode(base64_encode(hash('sha256', $codeVerifier))),
                            $authCode->getCodeChallenge()
                        ) === false
                    )
                        // InvalidGrant, Failed to verify `code_verifier`.
                        throw exOAuthServer::invalidGrant('Failed to verify `code_verifier`.', $this->newGrantResponse());
                    break;
                default:
                    throw exOAuthServer::serverError(sprintf(
                        'Unsupported code challenge method `%s`',
                        $authCode->getCodeChallengeMethod()
                    ), $this->newGrantResponse());
            }
        }
        
        ## Issue and persist access + refresh tokens

        $user = $this->repoUser->findOneByUID($authCode->getOwnerIdentifier());
        if (!$user instanceof iOAuthUser)
            // Resource Owner Not Found!!
            throw exOAuthServer::invalidRequest('code', 'Authorization code has expired', $this->newGrantResponse());
        
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

        // Revoke AuthCode
        $this->repoAuthCode->removeByIdentifier($authCodeIdentifier);

        $response = $grantResponse->toResponseWith($response);
        return $response;
    }


    /**
     * New Grant Response
     *
     * @return GrantResponseRedirect|GrantResponseJson
     * @throws \Exception
     */
    function newGrantResponse()
    {
        $request = $this->request;

        if ($this->_isAuthorizationRequest($request)) {
            $client    = $this->assertClient();
            $reqParams = $request->getQueryParams();
            $redirectUri  = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri'], null);
            if ($redirectUri === null) {
                $redirectUri = $client->getRedirectUri();
                if (is_array($redirectUri))
                    $redirectUri = current($redirectUri);
                elseif (\Poirot\Std\isStringify($redirectUri))
                    $redirectUri = (string) $redirectUri;
                else
                    throw new \Exception('Invalid Redirect Uri Provided by Client.');
            }

            // TODO what about assert clients??
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
                    // So we must not redirect back the error result to client
                    // responder as an argument are abandoned!!
                    throw exOAuthServer::invalidClient();
            }
            
            $grantRespose = new GrantResponseRedirect();
            $grantRespose->setRedirectUri($redirectUri);
            return $grantRespose;
        }

        return new GrantResponseJson();
    }

    /**
     * Issue Token and Persist It
     *
     * @param iOAuthClient $client
     * @param \DateInterval $authCodeTTL
     * @param iOAuthUser   $resourceOwner
     * @param string        $redirectUri
     * @param string        $codeChallenge
     * @param string        $codeChallengeMethod
     * @param array         $scopes
     * 
     * @return iEntityAccessToken
     */
    protected function issueAuthCode(iOAuthClient $client
        , \DateInterval $authCodeTTL
        , iOAuthUser $resourceOwner
        , $redirectUri
        , $scopes = array()
        , $codeChallenge = null
        , $codeChallengeMethod = null
    ) {
        $curTime = new \DateTime();
        $token = new AuthCode();
        $token
            ->setScopes($scopes)
            ->setClientIdentifier($client->getIdentifier())
            ->setExpiryDateTime($curTime->add($authCodeTTL))
            ->setOwnerIdentifier($resourceOwner->getUID())
            ->setRedirectUri($redirectUri)
        ;

        (!isset($codeChallenge))       ?: $token->setCodeChallenge($codeChallenge);
        (!isset($codeChallengeMethod)) ?: $token->setCodeChallengeMethod($codeChallengeMethod);
        
        $iToken = $this->repoAuthCode->insert($token);
        return $iToken;
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

    function setEnableCodeExchangeProof($flag = true)
    {
        $this->enableCodeExchangeProof = (boolean) $flag;
        return $this;
    }

    /**
     * Set Auth Code Time To Live
     *
     * @param \DateInterval $dateInterval
     *
     * @return $this
     */
    function setTtlAuthCode(\DateInterval $dateInterval)
    {
        $this->ttlAuthCode = $dateInterval;
        return $this;
    }

    /**
     * Get Auth Code Time To Live
     *
     * @return \DateInterval
     */
    function getTtlAuthCode()
    {
        if (!$this->ttlAuthCode)
            $this->setTtlAuthCode(new \DateInterval('PT5M'));

        return $this->ttlAuthCode;
    }

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
    
    /**
     * Set Callable To Retrieve Authenticated User Entity Object
     *
     * @param callable $callable
     *
     * @return $this
     */
    function setRetrieveUserCallback(/*callable*/ $callable)
    {
        if (!is_callable($callable))
            throw new \InvalidArgumentException(sprintf(
                'User Callback Must Be Callable; given: (%s).'
                , \Poirot\Std\flatten($callable)
            ));

        $this->retrieveUserCallback = $callable;
        return $this;
    }

    /**
     * User Entity
     *
     * @return iOAuthUser
     * @throws \Exception
     */
    function getUserEntity()
    {
        if (!$this->retrieveUserCallback)
            throw new \Exception('User Retrieve Callback Not Set.');

        $user = call_user_func($this->retrieveUserCallback);
        if (!$user instanceof iOAuthUser)
            throw exOAuthServer::accessDenied($this->newGrantResponse());

        return $user;
    }

    function setRepoRefreshToken(iRepoRefreshTokens $repoRefreshToken)
    {
        $this->repoRefreshToken = $repoRefreshToken;
        return $this;
    }

    function setRepoAuthCode(iRepoAuthCodes $repoAuthCode)
    {
        $this->repoAuthCode = $repoAuthCode;
        return $this;
    }

    function setRepoUser(iRepoUsers $repoUser)
    {
        $this->repoUser = $repoUser;
        return $this;
    }
}
