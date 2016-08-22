<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAuthCode;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityClient;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityUser;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoAuthCode;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoUser;
use Poirot\OAuth2\Model\AuthCode;
use Poirot\OAuth2\Model\RefreshToken;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Grant\Exception\exServerError;
use Poirot\OAuth2\Server\Response\GrantResponseBearerToken;
use Poirot\OAuth2\Server\Response\GrantResponseRedirect;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class GrantAuthCode
    extends aGrant
{
    /** @var iRepoRefreshToken */
    protected $repoRefreshToken;
    /** @var iRepoAuthCode */
    protected $repoAuthCode;
    /** @var iRepoUser */
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
        return $this->_isAuthorizationRequest($request) || $this->_isAccessTokenRequest($request);
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
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exInvalidRequest|exOAuthServer
     */
    function respond(ServerRequestInterface $request, ResponseInterface $response)
    {
        if ($this->_isAuthorizationRequest($request))
            return $this->_respondAuthorizationCode($request, $response);
        elseif ($this->_isAccessTokenRequest($request))
            return $this->_respondAccessToken($request, $response);
        else
            throw new exInvalidRequest;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exInvalidRequest|Exception\exInvalidClient|\Exception
     */
    function _respondAuthorizationCode(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client = $this->assertClient($request, false);
        $scopes = $this->assertScopes($request, $client->getScope());

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
                throw new exInvalidRequest;

            $codeChallengeMethod = \Poirot\Std\emptyCoalesce(@$reqParams['code_challenge_method'], 'plain');
            if (!in_array($codeChallengeMethod, array('plain', 'S256')))
                throw new exInvalidRequest;
        }


        # Finalize Response Contains Authorization Code

        $authCode = $this->issueAuthCode($client, $this->getTtlAuthCode(), $user, $redirect, $scopes, $codeChallenge, $codeChallengeMethod);

        $grantResponse = $this->newGrantResponse('authorization_code');
        $grantResponse->setExtraParams(array(
            'state' => $state,
            'code'  => $authCode->getIdentifier(),
        ));
        $grantResponse->setRedirectUri($redirect);

        $response = $grantResponse->putOn($response);
        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * 
     * @return ResponseInterface prepared response
     * @throws Exception\exInvalidClient
     * @throws \Exception
     * @throws exInvalidRequest
     * @throws exServerError
     */
    function _respondAccessToken(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client = $this->assertClient($request, true);

        $reqParams = (array) $request->getParsedBody();
        $authCodeIdentifier = \Poirot\Std\emptyCoalesce(@$reqParams['code']);
        if ($authCodeIdentifier === null)
            throw new exInvalidRequest;
        
        $authCode = $this->repoAuthCode->findByIdentifier($authCodeIdentifier);
        if (!$authCode instanceof iEntityAuthCode)
            // Code is Revoked!!
            throw new exInvalidRequest;

        if ($authCode->getClientIdentifier() !== $client->getIdentifier())
            // Authorization code was not issued to this client
            throw new exInvalidRequest;

        if ($authCode->getExpiryDateTime()->getTimestamp() < time())
            // Authorization code has expired
            throw new exInvalidRequest;

        $redirectUri = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri']);
        if ($authCode->getRedirectUri() !== $redirectUri)
            // Invalid redirect URI
            throw new exInvalidRequest;

        
        $scopes = $this->assertScopes($request, $client->getScope());


        ## Validate code challenge
        
        if ($this->enableCodeExchangeProof === true) {
            $codeVerifier = \Poirot\Std\emptyCoalesce(@$reqParams['code_verifier']);
            if ($codeVerifier === null)
                throw new exInvalidRequest;

            switch ($authCode->getCodeChallengeMethod()) {
                case 'plain':
                    if (hash_equals($codeVerifier, $authCode->getCodeChallenge()) === false)
                        // InvalidGrant, Failed to verify `code_verifier`.
                        throw new exInvalidRequest;
                    break;
                case 'S256':
                    if (
                        hash_equals(
                            urlencode(base64_encode(hash('sha256', $codeVerifier))),
                            $authCode->getCodeChallenge()
                        ) === false
                    )
                        // InvalidGrant, Failed to verify `code_verifier`.
                        throw new exInvalidRequest;
                    break;
                default:
                    throw new exServerError(
                        sprintf(
                            'Unsupported code challenge method `%s`',
                            $authCode->getCodeChallengeMethod()
                        )
                    );
            }
        }
        
        ## Issue and persist access + refresh tokens

        $user = $this->repoUser->findByIdentifier($authCode->getOwnerIdentifier());
        if (!$user instanceof iEntityUser)
            // Resource Owner Not Found!!
            throw new exInvalidRequest;
        
        $accToken      = $this->issueAccessToken($client, $this->getTtlAccessToken(), $user, $scopes);
        $refToken      = $this->issueRefreshToken($accToken, $this->getTtlRefreshToken());

        $grantResponse = $this->newGrantResponse('access_token');
        $grantResponse->setAccessToken($accToken);
        $grantResponse->setRefreshToken($refToken);

        // Revoke AuthCode
        $this->repoAuthCode->removeByIdentifier($authCodeIdentifier);

        $response = $grantResponse->putOn($response);
        return $response;
    }


    /**
     * New Grant Response
     *
     * @param string $responseType access_token|authorization_code
     *
     * @return GrantResponseRedirect|GrantResponseBearerToken
     * @throws \Exception
     */
    function newGrantResponse($responseType = 'access_token')
    {
        if ($responseType === 'access_token')
            return new GrantResponseBearerToken();
        elseif ($responseType === 'authorization_code')
            return new GrantResponseRedirect();

        throw new \Exception();
    }

    /**
     * Issue Token and Persist It
     *
     * @param iEntityClient $client
     * @param \DateInterval $authCodeTTL
     * @param iEntityUser   $resourceOwner
     * @param string        $redirectUri
     * @param string        $codeChallenge
     * @param string        $codeChallengeMethod
     * @param array         $scopes
     * 
     * @return iEntityAccessToken
     */
    protected function issueAuthCode(iEntityClient $client
        , \DateInterval $authCodeTTL
        , iEntityUser $resourceOwner
        , $redirectUri
        , $scopes = array()
        , $codeChallenge = null
        , $codeChallengeMethod = null
    ) {
        $token = new AuthCode();
        $token->setScopes($scopes);
        $token->setClientIdentifier($client->getIdentifier());
        $curTime = new \DateTime();
        $token->setExpiryDateTime($curTime->add($authCodeTTL));
        $token->setOwnerIdentifier($resourceOwner->getIdentifier());
        $token->setRedirectUri($redirectUri);
        
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
        $accessTokenData = \Poirot\Std\cast($accessToken)->toArray();
        
        $token = new RefreshToken($accessTokenData);
        $token->setAccessToken($accessToken);
        $curTime = new \DateTime();
        $token->setExpiryDateTime($curTime->add($refreshTokenTTL));

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
        if (!$this->ttlRefreshToken)
            $this->setTtlAuthCode(new \DateInterval('PT5M'));

        return $this->ttlRefreshToken;
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
     * @return iEntityUser
     * @throws \Exception
     */
    function getUserEntity()
    {
        if (!$this->retrieveUserCallback)
            throw new \Exception('User Retrieve Callback Not Set.');

        $user = call_user_func($this->retrieveUserCallback);
        if (!$user instanceof iEntityUser)
            throw new \LogicException(sprintf(
                'User Retrieve Callback Must Return iEntityUser Instance; given: (%s).'
                , \Poirot\Std\flatten($user)
            ));

        return $user;
    }

    function setRepoRefreshToken(iRepoRefreshToken $repoRefreshToken)
    {
        $this->repoRefreshToken = $repoRefreshToken;
        return $this;
    }

    function setRepoAuthCode(iRepoAuthCode $repoAuthCode)
    {
        $this->repoAuthCode = $repoAuthCode;
        return $this;
    }

    function setRepoUser(iRepoUser $repoUser)
    {
        $this->repoUser = $repoUser;
        return $this;
    }
}
