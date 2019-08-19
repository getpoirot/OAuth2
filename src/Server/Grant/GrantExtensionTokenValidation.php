<?php
namespace Poirot\OAuth2\Server\Grant;

use Module\OAuth2\Model\Entity\UserEntity;
use Poirot\OAuth2\Interfaces\Server\Repository\iOAuthClient;
use Poirot\OAuth2\Model\AccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoRefreshTokens;
use Poirot\OAuth2\Interfaces\Server\Repository\iRepoUsers;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\aGrantResponseAccessToken;
use Poirot\OAuth2\Server\Response\GrantResponseJson;

use Psr\Http\Message\ResponseInterface;


/**
 * Note: This effort could also be handled by an API gateway / service bus architecture.
 *
 * Request From Client Include Token:
 *
 *   POST http://authorization-server-host.com/auth/token HTTP/1.1
 *   Content-Type: application/x-www-form-urlencoded
 *   Authorization: Basic cnNfY2xpZW50OnBhc3N3b3Jk
 *
 *   grant_type=urn:poirot-framework.com:oauth2:grant_type:validate_bearer[&token=AA...ZZ][&refresh_token=AA..ZZ]
 *
 *
 * Successful Response Result In 200 OK:
 *
 *   HTTP/1.1 200 OK
 *   Content-Type: application/json;charset=UTF-8
 *
 *   {
 *     "access_token": { "resource_owner":"<resource_owner_id>", "extra":"<extra_data_of_token>" },
 *     "token_type":"Bearer",
 *     "expires_in":<time_remain_to_expire>,
 *     "scope":"<contains_token_scopes>",
 *     "client_id":"<token_client_id>"
 *   }
 */
class GrantExtensionTokenValidation
    extends aGrant
{
    const GrantType = 'urn:poirot-framework.com:oauth2:grant_type:validate_bearer';

    /** @var string|null */
    protected $grantTypeCustom;

    /** @var iRepoRefreshTokens */
    protected $repoRefreshToken;
    /** @var iRepoUsers */
    protected $repoUser;

    /** @var \DateInterval */
    protected $ttlRefreshToken;


    /**
     * @inheritDoc
     */
    function getGrantType()
    {
        return self::GrantType;
    }
    
    /**
     * @inheritDoc
     */
    function respond(ResponseInterface $response)
    {
        # Assert Client
        $client = $this->assertClient(true);
        $this->_validateClient($client);

        # Assert Token
        $request = $this->request;

        $requestParameters = (array) $request->getParsedBody();
        $pToken        = $requestParameters['token'] ?? null;
        $pRefreshToken = $requestParameters['refresh_token'] ?? null;

        if (empty($pToken) && empty($pRefreshToken))
            throw exOAuthServer::invalidRequest('"token" or "refresh_token"', null, $this->newGrantResponse());


        ## Retrieve Token Data
        $Scope = null;
        $ClientId = $client->getIdentifier();
        $AccessToken = [
            // extra data represent as json
            'resource_owner' => null,
        ];

        if ($pToken) {
            $token = $this->repoAccessToken->findByIdentifier($pToken);
            if (! $token instanceof iEntityAccessToken )
                // Token is Revoked!!
                throw exOAuthServer::invalidCredentials($this->newGrantResponse());

        } else if ($pRefreshToken) {
            $token = $this->repoRefreshToken->findByIdentifier($pRefreshToken);
            if (! $token instanceof iEntityRefreshToken )
                // Token is Revoked!!
                throw exOAuthServer::invalidCredentials($this->newGrantResponse());
        }

        $ExpireIn = $token->getDateTimeExpiration();
        $Scope    = $token->getScopes();

        $AccessToken['meta'] = [];
        if ( $token->isIssuedToResourceOwner() ) {
            $AccessToken['resource_owner'] = $uid = (string) $token->getOwnerIdentifier();

            /** @var UserEntity $user */
            $user = $this->repoUser->findOneByUID($uid);

            if ( false === $user )
                // Maybe User Deleted Or Something
                throw exOAuthServer::invalidCredentials($this->newGrantResponse());

            $AccessToken['meta'] = $user->getMeta();
        }

        # Issue Access Token

        $accToken = new AccessToken;
        $accToken
            ->setIdentifier(json_encode($AccessToken))
            ->setClientIdentifier($ClientId)
            ->setDateTimeExpiration($ExpireIn)
        ;

        $grantResponse = $this->newGrantResponse();
        $grantResponse->setAccessToken($accToken);
        $grantResponse->import(array(
            'scope' => implode(' ' /* Scope Delimiter */, $Scope),
        ));


        # Build Response

        $response = $grantResponse->toResponseWith($response);
        return $response;
    }
    
    /**
     * New Grant Response
     *
     * @return GrantResponseJson|aGrantResponseAccessToken
     */
    function newGrantResponse()
    {
        return new GrantResponseJson();
    }

    // Options:

    function setRepoUser(iRepoUsers $repoUser)
    {
        $this->repoUser = $repoUser;
        return $this;
    }

    function setRepoRefreshToken(iRepoRefreshTokens $repoRefreshToken)
    {
        $this->repoRefreshToken = $repoRefreshToken;
        return $this;
    }

    // ..

    /**
     * Validate Client Authorization For Grant Type
     *
     * @param iOAuthClient $client
     *
     * @throws exOAuthServer
     */
    private function _validateClient($client)
    {
        try
        {
            if (! $client->isResidentClient() )
                // Only Resident Clients (Clients belong to Resource Servers) Should Have Access!
                throw new \Exception;

            // Check IP Restriction Or Something Here; If Need !!
            // or Check Other Security Consideration ...

        } catch (\Exception $e) {
            throw exOAuthServer::invalidClient($this->newGrantResponse(), 'Only Resident Clients Allowed.');
        }
    }
}
