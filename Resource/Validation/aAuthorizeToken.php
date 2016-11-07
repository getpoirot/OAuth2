<?php
namespace Poirot\OAuth2\Resource\Validation;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\Error\DataErrorResponse;
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
     * @param ServerRequestInterface $request
     *
     * @return iEntityAccessToken
     * @throws exOAuthServer
     */
    abstract function hasValidated(ServerRequestInterface $request);

    /**
     * As per the Bearer spec (draft 8, section 2) - there are three ways for a client
     * to specify the bearer token, in order of preference: Authorization Header,
     * POST and GET.
     *
     * @param ServerRequestInterface $request
     *
     * @return string Token
     * @throws exOAuthServer
     */
    function assertAccessToken(ServerRequestInterface $request)
    {
        $token = null;

        # Get Token From Header:
        if ($header = $request->getHeaderLine('Authorization')) {
            if (!preg_match('/Bearer\s(\S+)/', $header, $matches))
                throw exOAuthServer::invalidRequest(null, 'Malformed auth header');

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

        if (!$token)
            /**
             * If no authentication is provided, set the status code
             * to 401 and return no other error information
             *
             * @see http://tools.ietf.org/html/rfc6750#section-3.1
             */
            throw new exOAuthServer(new DataErrorResponse, 401);

        return $token;
    }
}
