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

-export([ init/1, encode/3, get_key_authorization/2 ]).


% Not involving Myriad's parse transform here:
-type table( K, V ) :: map_hashtable:map_hashtable( K, V ).

% Silencing if not compiled with rebar3:
-export_type([ table/2 ]).


% Known keys:
%  - termsOfServiceAgreed :: boolean()
%  - contact :: ustring()
%
-type payload() :: table( atom(), term() ).

-type content() :: maybe( payload() ).


% Shorthands:
-type tls_private_key() :: letsencrypt:tls_private_key().
-type jws() :: letsencrypt:jws().



% Initializes a RSA JWS with specified private key.
-spec init( tls_private_key() ) -> jws().
init( _PrivateKey=#{ b64 := { N, E } } ) ->
	#jws{ alg='RS256',
		  jwk => #{ kty => 'RSA',
					<<"n">> => N,
					<<"e">> => E },
		  nonce => undefined }.



% Builds and returns the JWS body, see ref:
% https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2.
%
% Content is the payload (if any).
%
-spec encode( tls_private_key(), jws(), content() ) -> binary_b64().
encode( PrivateKey, Jws, Content ) ->

	Protected = letsencrypt_utils:jsonb64encode( Jws ),

	Payload = case Content of

		% For POST-as-GET queries, payload is just an empty string:
		undefined ->
			<<>>;

		_ ->
			letsencrypt_utils:jsonb64encode( Content )

	end,

	Signed = crypto:sign( rsa, sha256, <<Protected/binary, $., Payload/binary>>,
						  PrivateKey#tls_private_key.raw,

	EncSigned = letsencrypt_utils:b64encode( Signed ),

	json_utils:to_json( #{ <<"protected">> => Protected,
						   <<"payload">> => Payload,
						   <<"signature">> => EncSigned } ).



% Builds and returns the ACME key authorization.
%
% See https://www.rfc-editor.org/rfc/rfc8555.html#section-8.1.
%
-spec get_key_authorization( key(), token() ) -> binary().
get_key_authorization( #key{ kty=Kty, n=N, e=E }, Token ) ->

	Thumbprint = json_utils:to_json( #{ <<"kty">> => Kty, <<"n">> => N,
										<<"e">> => E } ),

	ThumbprintHash = crypto:hash( sha256, Thumbprint ),

	B64Hash = letsencrypt_utils:b64encode( ThumbprintHash ),

	<<Token/binary, $., B64Hash/binary>>.
