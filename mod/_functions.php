<?php
namespace Module\OAuth2Client
{
    use Poirot\Application\Exception\exAccessDenied;
    use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;

    function validateGivenToken(iEntityAccessToken $token = null, $tokenCondition)
    {
        if (!$token instanceof iEntityAccessToken)
            throw new exAccessDenied('Token is revoked or mismatch.');


        if ($tokenCondition) {
            # Check Resource Owner
            if ( $tokenCondition->mustHaveOwner && empty($token->getOwnerIdentifier()) )
                throw new exAccessDenied('Token Not Granted To Resource Owner; But Have To.');

            # Check Scopes
            if (!empty($tokenCondition->scopes)) {
                // TODO check scopes
                kd(array_intersect($tokenCondition->scopes, $token->getScopes()));
            }
        }
    };

    function functorValidateGivenToken($tokenCondition)
    {
        return function (iEntityAccessToken $token = null) use ($tokenCondition) {
            validateGivenToken($token, $tokenCondition);
        };
    }
}
