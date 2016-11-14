<?php
namespace Poirot\OAuth2\Server\Exception;

use Poirot\OAuth2\Server\Response\aGrantResponse;
use Poirot\OAuth2\Server\Response\Error\DataErrorResponse;
use Poirot\OAuth2\Server\Response\GrantResponseJson;
use Psr\Http\Message\ResponseInterface;

class exOAuthServer 
    extends \Exception
{
    /** @var DataErrorResponse */
    protected $dataError;
    protected $httpResponseCode = 400;
    /** @var aGrantResponse */
    protected $responder;


    /**
     * exOAuthServer constructor.
     *
     * @param DataErrorResponse $dataError
     * @param int $responseCode
     * @param aGrantResponse $responder
     */
    final function __construct(DataErrorResponse $dataError, $responseCode = 400, aGrantResponse $responder = null)
    {
        $this->dataError = $dataError;
        $this->httpResponseCode = $responseCode;
        $this->responder = $responder;
        
        parent::__construct($dataError->getErrorDescription(), $responseCode);
    }

    /**
     * Manipulate Response To Achieve Satisfiable
     * Response With Given Options.
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface Clone copy
     * @throws \Exception
     */
    function buildResponse(ResponseInterface $response)
    {
        if (!$this->responder)
            $this->responder = new GrantResponseJson;
        
        
        $this->responder->import($this->dataError);
        $response = $this->responder->toResponseWith($response);
        return $response;
    }
    
    function setResponder(aGrantResponse $responder)
    {
        $this->responder = $responder;
        return $this;
    }
    
    function getError()
    {
        return $this->dataError;
    }
    
    // ..

    /**
     * Server error.
     *
     * @param $hint
     * @param aGrantResponse $responder
     *
     * @return static
     */
    static function serverError($hint = null, aGrantResponse $responder = null)
    {
        $err = new DataErrorResponse();
        $err->setError($err::ERR_SERVER_ERROR);
        $err->setHint($hint);
        $err->setErrorDescription(
            'The authorization server encountered an unexpected condition which prevented it from fulfilling.'
        );
        
        return new static(
            $err
            , 500
            , $responder
        );
    }

    /**
     * Unsupported grant type error.
     *
     * @param aGrantResponse $responder
     *
     * @return static
     */
    static function unsupportedGrantType(aGrantResponse $responder = null)
    {
        $err = new DataErrorResponse();
        $err->setError($err::ERR_UNSUPPORTED_GRANT_TYPE);
        $err->setHint('Check the `grant_type` parameter');
        $err->setErrorDescription(
            'The authorization grant type is not supported by the authorization server.'
        );

        return new static(
            $err
            , 400
            , $responder
        );
    }

    /**
     * Invalid request error.
     *
     * @param string $parameter The invalid parameter
     * @param null|string $hint
     * @param aGrantResponse $responder
     *
     * @return static
     */
    static function invalidRequest($parameter, $hint = null, aGrantResponse $responder = null)
    {
        $errorMessage = 'The request is missing a required parameter, includes an invalid parameter value, ' .
            'includes a parameter more than once, or is otherwise malformed.';
        $hint = ($hint === null) ? sprintf('Check the `%s` parameter', $parameter) : $hint;

        $err = new DataErrorResponse();
        $err->setError($err::ERR_INVALID_REQUEST);
        $err->setErrorDescription($errorMessage);
        $err->setHint($hint);

        return new static(
            $err
            , 400
            , $responder
        );
    }

    /**
     * Invalid client error.
     *
     * @param aGrantResponse $responder
     *
     * @return static
     */
    static function invalidClient(aGrantResponse $responder = null)
    {
        $errorMessage = 'Client authentication failed';

        $err = new DataErrorResponse();
        $err->setError($err::ERR_INVALID_CLIENT);
        $err->setErrorDescription($errorMessage);

        return new static(
            $err
            , 401
            , $responder
        );
    }

    /**
     * Invalid grant.
     *
     * @param string $hint
     * @param aGrantResponse $responder
     *
     * @return static
     */
    static function invalidGrant($hint = '', aGrantResponse $responder = null)
    {
        $errorMessage = 'The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token '
            . 'is invalid, expired, revoked, does not match the redirection URI used in the authorization request, '
            . 'or was issued to another client.';

        $err = new DataErrorResponse();
        $err->setError($err::ERR_INVALID_GRANT);
        $err->setErrorDescription($errorMessage);
        $err->setHint($hint);

        return new static(
            $err
            , 400
            , $responder
        );
    }

    /**
     * Invalid credentials error.
     *
     * @param aGrantResponse $responder
     *
     * @return static
     */
    static function invalidCredentials(aGrantResponse $responder = null)
    {
        $err = new DataErrorResponse();
        $err->setError($err::ERR_UNAUTHORIZED_CLIENT);
        $err->setErrorDescription('The user credentials were incorrect.');

        return new static(
            $err
            , 401
            , $responder
        );
    }

    /**
     * Invalid refresh token.
     *
     * @param null|string $hint
     * @param aGrantResponse $responder
     *
     * @return static
     */
    static function invalidRefreshToken($hint = null, aGrantResponse $responder = null)
    {
        $err = new DataErrorResponse();
        $err->setError($err::ERR_INVALID_REQUEST);
        $err->setErrorDescription('The refresh token is invalid.');
        $err->setHint($hint);

        return new static(
            $err
            , 400
            , $responder
        );
    }

    /**
     * Access denied.
     *
     * @param aGrantResponse $responder
     * 
     * @return static
     */
    static function accessDenied(aGrantResponse $responder = null)
    {
        $err = new DataErrorResponse();
        $err->setError($err::ERR_INVALID_GRANT);
        $err->setErrorDescription('The resource owner or authorization server denied the request.');

        return new static(
            $err
            , 400
            , $responder
        );
    }
}
