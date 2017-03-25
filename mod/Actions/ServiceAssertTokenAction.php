<?php
namespace Module\OAuth2Client\Actions;

use Module\OAuth2Client\Services\IOC;
use Poirot\Application\aSapi;
use Poirot\Http\Interfaces\iHttpRequest;
use Poirot\Http\Psr\ServerRequestBridgeInPsr;
use Poirot\Ioc\Container\Service\aServiceContainer;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Model\AccessToken;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\Std\Struct\DataEntity;


class ServiceAssertTokenAction
    extends aServiceContainer
{
    const CONF_KEY = 'ServiceAssertToken';


    /** @var string Service Name */
    protected $name = 'assertToken';


    /**
     * Create Service
     *
     * @return callable
     */
    function newService()
    {
        $config = $this->_attainConf();


        # Check Debug Mode:

        $token  = null;

        if (isset($config['debug_mode']) && $config['debug_mode']['enabled'])
        {
            // Mock Debuging Mode
            $accToken = new AccessToken;

            $exprDateTime = __( new \DateTime() )
                ->add( new \DateInterval(sprintf('PT%sS', 1000)) );

            $token = $config['debug_mode']['token'];

            $accToken
                ->setDateTimeExpiration($exprDateTime)
                ->setClientIdentifier($token['client_identifier'])
                ->setOwnerIdentifier($token['owner_identifier'])
                ->setScopes($token['scopes'])
            ;

        }

        /**
         * Assert Authorization Token From Request
         *
         * @param iHttpRequest $request
         *
         * @return iEntityAccessToken
         */
        return function (iHttpRequest $request) use ($token)
        {
            if ($token)
                // Debug Mode, Token is Mocked!!
                return $token;


            # Retrieve Token Assertion From OAuth Resource Server
            $validator  = IOC::AuthorizeToken();

            try {
                $token = $validator->hasValidated( new ServerRequestBridgeInPsr($request) );

                // TODO check scope

            } catch (exOAuthServer $e) {
                // any oauth server error will set token result to false
                $token = false;
            }

            return $token;
        };
    }


    // ..

    /**
     * Attain Merged Module Configuration
     * @return array
     */
    protected function _attainConf()
    {
        $sc     = $this->services();
        /** @var aSapi $sapi */
        $sapi   = $sc->get('/sapi');
        /** @var DataEntity $config */
        $config = $sapi->config();
        $config = $config->get(\Module\OAuth2Client\Module::CONF_KEY);

        $r = array();
        if (is_array($config) && isset($config[static::CONF_KEY]))
            $r = $config[static::CONF_KEY];

        return $r;
    }
}
