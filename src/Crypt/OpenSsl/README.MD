Generating public and private keys

To generate the private key run this command on the terminal:
``openssl genrsa -out private.key 1024``

If you want to provide a passphrase for your private key run this command instead:
``openssl genrsa -passout pass:_passphrase_ -out private.key 1024``

then extract the public key from the private key:
``openssl rsa -in private.key -pubout -out public.key``

or use your passphrase if provided on private key generation:
``openssl rsa -in private.key -passin pass:_passphrase_ -pubout -out public.key``

The private key must be kept secret (i.e. out of the web-root of the authorization server). The authorization server also requires the public key.

If a passphrase has been used to generate private key it must be provided to the authorization server.

The public key should be distributed to any services (for example resource servers) that validate access tokens.