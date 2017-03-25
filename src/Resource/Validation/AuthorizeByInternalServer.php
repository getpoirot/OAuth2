<?php
namespace Poirot\OAuth2\Resource\Validation;


use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoAccessTokens;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizeByInternalServer
    extends aAuthorizeToken
{
    /** @var iRepoAccessTokens */
    protected $_accessTokens;


    /**
     * AuthorizeByInternalServer constructor.
     *
     * @param iRepoAccessTokens $accessTokens
     */
    function __construct(iRepoAccessTokens $accessTokens)
    {
        $this->_accessTokens = $accessTokens;
    }

    /**
     * Validate Authorize Token With OAuth Server
     *
     * note: implement grant extension http request
     *
     * @param ServerRequestInterface $request
     *
     * @return iEntityAccessToken
     * @throws exOAuthServer
     */
    function hasValidated(ServerRequestInterface $request)
    {
        $token = $this->assertAccessToken($request);
        if (false === $token = $this->_accessTokens->findByIdentifier($token))
            throw exOAuthServer::accessDenied();

        return $token;
    }
}
