<?php
namespace Poirot\OAuth2\Server\Grant\Exception;

class exServerError
    extends exOAuthServer
{
    const EXCEPTION_DEFAULT_MESSAGE = 'The request is missing a required parameter, includes an invalid parameter value, \' .
            \'includes a parameter more than once, or is otherwise malformed.\';';

    const EXCEPTION_DEFAULT_CODE    = 400;

}
