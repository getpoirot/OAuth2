<?php
namespace Poirot\OAuth2\Resource\Validation;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Called when a user should be authorized by an authorization server.
 *
 */
abstract class aAuthorizeToken
{
    /**
     * Validate Authorize Token With OAuth Server
     *
     * note: implement grant extension http request
     *
     * @param string $token
     *
     * @return iEntityAccessToken
     * @throws exOAuthServer Access Denied
     */
    abstract function assertToken($token);

    /**
     * As per the Bearer spec (draft 8, section 2) - there are three ways for a client
     * to specify the bearer token, in order of preference: Authorization Header,
     * POST and GET.
     *
     * @param ServerRequestInterface $request
     *
     * @return null|string Token
     * @throws exOAuthServer
     */
    function parseTokenFromRequest(ServerRequestInterface $request)
    {
        $token = null;

        # Get Token From Header:
        if ($header = $request->getHeaderLine('Authorization')) {
            if (!preg_match('/Bearer\s(\S+)/', $header, $matches))
                throw exOAuthServer::invalidRequest(null, 'Malformed auth Bearer header.');

            return $token = $matches[1];
        }


        # Get Token From POST:
        if (strtolower($request->getMethod()) === 'post'
            && $contentType = $request->getHeaderLine('Content-Type')
        ) {
            if ($contentType != 'application/x-www-form-urlencoded')
                exOAuthServer::invalidRequest(null, 'The content type for POST requests must be "application/x-www-form-urlencoded"');

            $postData = $request->getParsedBody();
            foreach ($postData as $k => $v) {
                if ($k !== 'access_token') continue;

                return $token = $v;
            }
        }


        # Get Token From GET:
        $queryData = $request->getQueryParams();
        $token     = (isset($queryData['access_token'])) ? $queryData['access_token'] : null;
        return $token;
    }
}
