%% Copyright 2015-2020 Guillaume Bour
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.


% Manages JSON Web Signatures (JWS).
%
% See https://en.wikipedia.org/wiki/JSON_Web_Signature
%
-module(letsencrypt_jws).

-author("Guillaume Bour <guillaume@bour.cc>").

-export([ init/1, encode/3, keyauth/2 ]).


% Known keys:
%  termsOfServiceAgreed => boolean()
%  contact => ustring()
%
-type payload() :: table( atom(), term() ).

-type content() :: payload() | 'empty'.


% Shorthands:
-type ssl_private_key() :: letsencrypt:ssl_private_key().
-type jws() :: letsencrypt:jws().



% Initializes a RSA JWS with specified private key.
-spec init( ssl_private_key() ) -> jws().
init( _PrivateKey=#{ b64 := { N, E } } ) ->
	#{ alg => 'RS256',
	   jwk => #{ kty => 'RSA',
				 <<"n">> => N,
				 <<"e">> => E },
	   nonce => undefined }.



% Builds and returns the JWS body, see ref:
% https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2.
%
-spec encode( ssl_private_key(), jws(), content() ) -> binary().
encode( _PrivateKey=#{ raw := RSAKey }, Jws, Content ) ->

	Protected = letsencrypt_utils:jsonb64encode( Jws ),

	Payload = case Content of

		% For POST-as-GET queries, payload is just an empty string:
		empty ->
			<<>>;

		_ ->
			letsencrypt_utils:jsonb64encode( Content )

	end,

	Signed = crypto:sign( rsa, sha256, <<Protected/binary, $., Payload/binary>>,
						  RSAKey ),

	EncSigned = letsencrypt_utils:b64encode( Signed ),

	json_utils:to_json( #{ <<"protected">> => Protected,
						   <<"payload">> => Payload,
						   <<"signature">> => EncSigned } ).



% Builds and returns ACME key authorization.
%
% See https://www.rfc-editor.org/rfc/rfc8555.html#section-8.1.
%
keyauth( _Key=#{ <<"e">> := E, <<"n">> := N, <<"kty">> := Kty }, Token ) ->

	Thumbprint = json_utils:to_json( #{ <<"e">> => E, <<"kty">> => Kty,
										<<"n">> => N } ),

	ThumbprintHash = crypto:hash( sha256, Thumbprint ),

	EncHash = letsencrypt_utils:b64encode( ThumbprintHash ),

	<<Token/binary, $., EncHash/binary>>.
