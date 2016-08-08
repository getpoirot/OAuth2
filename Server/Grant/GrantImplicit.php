<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityUser;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\GrantResponseRedirect;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class GrantImplicit
    extends aGrant
{
    /** @var callable */
    protected $retrieveUserCallback;

    
    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    function getGrantType()
    {
        return 'implicit';
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
        $requestParameters = $request->getQueryParams();
        $responseType      = \Poirot\Std\emptyCoalesce(@$requestParameters['response_type']);
        $clientIdentifier  = \Poirot\Std\emptyCoalesce(@$requestParameters['client_id']);

        return ($responseType === 'token' && $clientIdentifier !== null);
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
        $client = $this->assertClient($request, false);
        $scopes = $this->assertScopes($request, $client->getScope());

        // The user approved the client, redirect them back with an access token
        $user = $this->getUserEntity();
        
        $reqParams = $request->getQueryParams();
        $redirect  = \Poirot\Std\emptyCoalesce(@$reqParams['redirect_uri']);
        $redirect  = \Poirot\Std\emptyCoalesce( $redirect, current($client->getRedirectUri()) );
        $state     = \Poirot\Std\emptyCoalesce(@$reqParams['state']);

        $accToken  = $this->issueAccessToken($client, $this->getTtlAccessToken(), $user, $scopes);

        $grantResponse = $this->newGrantResponse();
        $grantResponse->setAccessToken($accToken);
        $grantResponse->setExtraParams(array('state' => $state));
        $grantResponse->setRedirectUri($redirect);
        
        $response = $grantResponse->putOn($response);
        return $response;
    }
    
    /**
     * New Grant Response
     *
     * @return GrantResponseRedirect
     */
    function newGrantResponse()
    {
        return new GrantResponseRedirect();
    }


    // Options:

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
}
