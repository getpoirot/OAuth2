<?php
namespace Poirot\OAuth2\Resource\Validation;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Model\AccessToken;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Grant\GrantExtensionTokenValidation;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Validate Authorize By Registered Extension Grant
 * it will send http request of grant type match with
 * related registered extension in oauth server
 *
 * @see GrantExtensionTokenValidation
 */
class AuthorizeByRemoteServer
    extends aAuthorizeToken
{
    protected $endpointToken;
    protected $authorization;
    protected $grantType;


    /**
     * AuthorizeByRemoteServer constructor.
     *
     * @param string $oauthTokenEndpoint  OAuth server Token endpoint; exp. http://auth/token
     * @param string $authorizationHeader Stringify Authorization Header; exp. Authorization: Basic uyyu=
     * @param string $grantType           GrantType extension registered name
     */
    function __construct($oauthTokenEndpoint, $authorizationHeader, $grantType = GrantExtensionTokenValidation::TYPE_GRANT)
    {
        $this->endpointToken = $oauthTokenEndpoint;
        $this->authorization = $authorizationHeader;
        $this->grantType     = $grantType;
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
        $token  = $this->assertAccessToken($request);
        $result = $this->_sendByCurl($token);


        # Extract Result Data:
        if (! $result = json_decode($result))
            throw exOAuthServer::serverError('Unexpected Result From Authorization Server.');

        if (isset($result->error))
            throw exOAuthServer::serverError($result->error.': '.$result->error_description);

        if (!$extra  = json_decode($result->access_token))
            throw exOAuthServer::serverError('Mismatch Token Response Structure Data; cant parse extra.');

        $result = \Poirot\Std\toArrayObject($result);
        $extra  = \Poirot\Std\toArrayObject($extra);

        $result = array_merge($result, $extra);
        unset($result['access_token']);

        $token  = new AccessToken($result);
        return $token;
    }

    /**
     * Send Token Over Wire By Curl
     * @param $token
     * @return mixed
     * @throws exOAuthServer
     */
    protected function _sendByCurl($token)
    {
        # Connect To Remote Server and Retrieve Token Request Result as Extension:
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $this->endpointToken);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS
            , http_build_query(array(
                // form data
                'grant_type' => $this->grantType,
                'token'      => $token,
            ))
        );
        curl_setopt($ch, CURLOPT_HTTPHEADER
            , array(
                'Authorization: '.$this->authorization,
                'Connection: close'
            )
        );

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $result = curl_exec ($ch);
        if ($err = curl_error($ch))
            throw exOAuthServer::serverError('Error while connecting to Authorization Server.');

        curl_close ($ch);

        return $result;
    }
}
