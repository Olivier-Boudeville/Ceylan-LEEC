%% Copyright 2015-2021 Guillaume Bour
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

% Copyright (C) 2020-2023 Olivier Boudeville
%
% This file is part of the Ceylan-LEEC library, a fork of the Guillaume Bour's
% letsencrypt-erlang library, released under the same licence.
%
% This file was forked on 2020.


% @doc This module manages <b>JSON Web Signatures</b> (JWS).
%
% See [https://en.wikipedia.org/wiki/JSON_Web_Signature].
%
-module(leec_jws).

% Original work:
-author("Guillaume Bour (guillaume at bour dot cc)").

% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com)").


-export([ init/1, encode/4, get_key_authorization/3 ]).


% For the records introduced:
-include("leec.hrl").


-type payload() :: table( atom(), term() ).
% Known keys:
%  - termsOfServiceAgreed :: boolean()
%  - contact :: ustring()


-type content() :: maybe( payload() ).


% Shorthands:

-type jws() :: leec:jws().
-type leec_http_state() :: leec:leec_http_state().

-type tls_private_key() :: leec:tls_private_key().
-type tls_public_key() :: leec:tls_public_key().



% @doc Initializes a RSA JWS with specified TLS private key.
-spec init( tls_private_key() ) -> jws().
init( #tls_private_key{ b64_pair={ N, E } } ) ->
	#jws{ alg='RS256',
		  jwk=#tls_public_key{ kty='RSA', n=N, e=E },
		  nonce=undefined }.



% @doc Builds and returns the JWS body.
%
% See [https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2].
%
% Content is the payload (if any).
%
-spec encode( tls_private_key(), jws(), content(), leec_http_state() ) ->
					leec:binary_b64().
encode( PrivateKey, Jws, Content,
		#leec_http_state{ json_parser_state=ParserState } ) ->

	cond_utils:if_defined( leec_debug_codec, trace_bridge:debug_fmt(
		"Encoding to JSON following JWS:~n  ~p~n with content: ~p",
		[ Jws, Content ] ) ),

	Protected = leec_utils:jsonb64encode( jws_to_map( Jws ), ParserState ),

	Payload = case Content of

		% For POST-as-GET queries, payload is just an empty string:
		undefined ->
			<<>>;

		_ ->
			leec_utils:jsonb64encode( Content, ParserState )

	end,

	Signed = crypto:sign( rsa, sha256, <<Protected/binary, $., Payload/binary>>,
						  PrivateKey#tls_private_key.raw ),

	EncSigned = leec_utils:b64encode( Signed ),

	json_utils:to_json( #{ <<"protected">> => Protected,
						   <<"payload">> => Payload,
						   <<"signature">> => EncSigned }, ParserState ).



% @doc Builds and returns the ACME key authorization.
%
% See [https://www.rfc-editor.org/rfc/rfc8555.html#section-8.1].
%
-spec get_key_authorization( tls_public_key(), leec:token(),
							 leec_http_state() ) -> leec:key_auth().
get_key_authorization( #tls_public_key{ kty=Kty, n=N, e=E }, Token,
					   #leec_http_state{ json_parser_state=ParserState } ) ->

	Thumbprint = json_utils:to_json( #{ <<"kty">> => Kty, <<"n">> => N,
										<<"e">> => E }, ParserState ),

	ThumbprintHash = crypto:hash( sha256, Thumbprint ),

	B64Hash = leec_utils:b64encode( ThumbprintHash ),

	<<Token/binary, $., B64Hash/binary>>.



% @doc Returns a map-based version of the specified JSON Web Signature record,
% typically for encoding.
%
-spec jws_to_map( jws() ) -> map().
jws_to_map( #jws{ alg=Alg, url=MaybeUrl, kid=MaybeKid, jwk=MaybeJwk,
				  nonce=MaybeNonce } ) ->

	AlgMap = #{ alg => Alg },

	UrlMap = case MaybeUrl of

		undefined ->
			AlgMap;

		Url ->
			AlgMap#{ url => Url }

	end,

	KidMap = case MaybeKid of

		undefined ->
			UrlMap;

		Kid ->
			UrlMap#{ kid => Kid }

	end,

	JwkMap = case MaybeJwk of

		undefined ->
			KidMap;

		Jwk ->
			KidMap#{ jwk => leec_tls:key_to_map( Jwk ) }

	end,

	case MaybeNonce of

		undefined ->
			JwkMap;

		Nonce ->
			JwkMap#{ nonce => Nonce }

	end.
