<?php
namespace Module\OAuth2Client\Actions
{
    use Poirot\Http\Interfaces\iHttpRequest;


    /**
     * @property callable $AssertToken
     *
     * @method static callable AssertToken(iHttpRequest $request)
     */
    class IOC extends \IOC
    { }
}


namespace Module\OAuth2Client\Services
{
    use Poirot\OAuth2\Resource\Validation\aAuthorizeToken;
    use Poirot\OAuth2\Resource\Validation\AuthorizeByInternalServer;
    use Poirot\OAuth2\Resource\Validation\AuthorizeByRemoteServer;

    /**
     * @method static aAuthorizeToken|AuthorizeByRemoteServer|AuthorizeByInternalServer AuthorizeToken()
     */
    class IOC extends \IOC
    { }
}
