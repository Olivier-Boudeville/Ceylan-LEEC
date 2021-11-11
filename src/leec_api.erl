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

% Copyright (C) 2020-2021 Olivier Boudeville
%
% This file is part of the Ceylan-LEEC library, a fork of the Guillaume Bour's
% letsencrypt-erlang library, released under the same licence.


% @doc This module centralises the main functions regarding the <b>API used to
% interact with ACME servers</b>.
%
-module(leec_api).

% Original work:
-author("Guillaume Bour (guillaume at bour dot cc)").

% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com").


-export([ get_directory_map/3, get_nonce/3, get_acme_account/5,
		  request_new_certificate/6, get_order/5, request_authorization/5,
		  notify_ready_for_challenge/5, finalize_order/6, get_certificate/5,
		  binary_to_status/1,
		  get_tcp_connection/4, close_tcp_connections/1 ]).

-compile( { nowarn_unused_function,
			[ request_via_shotgun/6, request_via_native_httpc/6 ] } ).


-type http_body() :: map().
% Key :: Value entries being typically:
%
%  - body :: body()
%
%  - headers :: headers()
%
%  - location :: location()
%
%  - nonce :: nonce()
%
%  - status_code: http_status_code()


-type json_http_body() :: http_body().
% Additional 'json' key, whose value is the body once decoded from JSON.

-type header_map() :: map().

-type bin_content() :: binary().

-type cert_req_option_map() :: leec:cert_req_option_map().

-type environment() :: 'default' | 'staging'.
% Not 'prod'.


% For the records introduced:
-include("leec.hrl").


% Shorthands:

-type bin_string() :: text_utils:bin_string().

-type body() :: web_utils:body().
-type nonce() :: web_utils:nonce().
-type http_status_code() :: web_utils:http_status_code().

-type challenge() :: leec:challenge().
-type uri() :: leec:uri().
-type bin_uri() :: leec:bin_uri().
-type tls_private_key() :: leec:tls_private_key().
-type tcp_connection_cache() :: leec:tcp_connection_cache().
-type bin_domain() :: leec:bin_domain().
-type bin_key() :: leec:bin_key().
-type bin_csr_key() :: leec:bin_csr_key().
-type directory_map() :: leec:directory_map().
-type json_map_decoded() :: leec:json_map_decoded().
-type jws() :: leec:jws().
-type order_map() :: leec:order_map().
-type bin_certificate() :: leec:bin_certificate().
-type le_state() :: leec:le_state().


-ifdef(TEST).

	-define( staging_api_url, <<"https://127.0.0.1:14000/dir">> ).
	-define( default_api_url, <<"">> ).

-else.

	-define( staging_api_url,
			 <<"https://acme-staging-v02.api.letsencrypt.org/directory">> ).

	-define( default_api_url,
			 <<"https://acme-v02.api.letsencrypt.org/directory">> ).

-endif.



% @doc Returns the status corresponding to specified binary string.
-spec binary_to_status( bin_string() ) -> leec:status().
binary_to_status( <<"pending">> ) ->
	pending;

binary_to_status( <<"processing">> ) ->
	processing;

binary_to_status( <<"valid">> ) ->
	valid;

binary_to_status( <<"invalid">> ) ->
	invalid;

binary_to_status( <<"revoked">> ) ->
	revoked;

binary_to_status( InvalidBinStatus ) ->
	trace_bridge:error_fmt( "Invalid status: '~p'.", [ InvalidBinStatus ] ),
	throw( { invalid_status, InvalidBinStatus } ).



%% Private section.


% @doc Returns a suitable TCP connection.
%
% If a connection to the given Proto://Host:Port is already opened, returns it,
% otherwise returns a newly opened connection.
%
% TODO: check connection is still alive (ping?)
%
% Note: for long-living processes (ex: up to 90 days can elapse between two
% certification generations for a given domain), it is certainly safer to reset
% that connection cache.
%
-spec get_tcp_connection( net_utils:protocol_type(),
		net_utils:string_host_name(), net_utils:tcp_port(),
		tcp_connection_cache() ) ->
							{ shotgun:connection(), tcp_connection_cache() }.
get_tcp_connection( Proto, Host, Port, TCPCache ) ->

	ConnectTriplet = { Proto, Host, Port },

	case table:lookup_entry( ConnectTriplet, TCPCache ) of

		key_not_found ->

			cond_utils:if_defined( leec_debug_network,
			  trace_bridge:debug_fmt( "[~w] Opening a connection to ~ts:~B, "
				"with the '~ts' scheme.", [ self(), Host, Port, Proto ] ) ),

			Conn = case shotgun:open( Host, Port, Proto ) of

				{ ok, Connection } ->
					Connection;

				{ error, gun_open_failed } ->
					trace_bridge:error_fmt( "[~w] Connection to ~ts:~B, "
						"with the '~ts' scheme, failed.",
						[ self(), Host, Port, Proto ] ),
				   throw( { gun_open_failed, Host, Port, Proto } );

				{ error, Error } ->
					trace_bridge:error_fmt( "[~w] Connection to ~ts:~B, "
						"with the '~ts' scheme, failed: ~p.",
						[ self(), Host, Port, Proto, Error ] ),
				   throw( { gun_open_failed, Error, Host, Port, Proto } )

			end,

			cond_utils:if_defined( leec_debug_network,
			  trace_bridge:debug_fmt( "[~w] Connection ~p obtained and cached.",
									  [ self(), Conn ] ) ),

			{ Conn, table:add_entry( ConnectTriplet, Conn, TCPCache ) };


		{ value, Conn } ->
			cond_utils:if_defined( leec_debug_network,
			  trace_bridge:debug_fmt( "[~w] Reusing connection to ~ts:~B, "
				  "with the '~ts' scheme: ~w.",
				  [ self(), Host, Port, Proto, Conn ] ) ),
			{ Conn, TCPCache }

	end.



% @doc Closes all pending (cached) TCP connections.
-spec close_tcp_connections( tcp_connection_cache() ) -> void().
close_tcp_connections( TCPCache ) ->

	cond_utils:if_defined( leec_debug_network,
		trace_bridge:debug_fmt( "[~w] Closing all TCP connections.",
								[ self() ] ) ),

	% Not testing any returned close error, needing to resist them:
	[ shotgun:close( Conn ) || Conn <- table:values( TCPCache ) ].




% @doc Decodes the http body as JSON if requested in options, or returns it as
% is.
%
% Returns that response, with added JSON structure if required.
%
-spec decode( CertReqOptionMap :: cert_req_option_map(), Response :: map(),
			  le_state() ) -> json_http_body().
decode( _CertReqOptionMap=#{ json := true }, Response=#{ body := Body },
		#le_state{ json_parser_state=ParserState } ) ->

	cond_utils:if_defined( leec_debug_codec,
		trace_bridge:debug_fmt( "Decoding from JSON following body:~n~p",
								[ Body ] ) ),

	Payload = json_utils:from_json( Body, ParserState ),

	cond_utils:if_defined( leec_debug_codec,
		trace_bridge:debug_fmt( "Payload decoded from JSON:~n  ~p",
								[ Payload ] ) ),

	Response#{ json => Payload };

decode( _CertReqOptionMap, Response, _LEState ) ->

	cond_utils:if_defined( leec_debug_codec,
		trace_bridge:debug_fmt( "Not requested to decode from JSON following "
			"response:~n~p", [ Response ] ) ),

	Response.



% @doc Queries the specified URI (GET or POST) and returns the corresponding
% result, with an updated state.
%
% Returned result:
%   {ok, #{status_code, body, headers}}: query succeeded
%   {error, invalid_method}           : method must be either 'get' or 'post'
%   {error, term()}                   : query failed
%
% TODO: is 'application/jose+json' content type always required?
% (check ACME documentation)
%
-spec request( 'get' | 'post', uri(), header_map(), maybe( bin_content() ),
			   cert_req_option_map(), le_state() ) -> { body(), le_state() }.
request( Method, Uri, Headers, MaybeBinContent, CertReqOptionMap, LEState ) ->

	trace_bridge:warning_fmt( "Request of type ~p to ~p relies on options ~p.",
							  [ Method, Uri, CertReqOptionMap ] ),

	% We used to introduce in these implementations an (optional) waiting (with
	% timer:sleep/1), as we could see, when using an ACME server in production
	% (not staging) mode, a 'too many requests' error (code 429: client-side
	% error), whereas no other interaction with the ACME server was taking
	% place. However we found out since then it was another, unrelated rate
	% limit that applied, so this would be of no use.

	cond_utils:if_set_to( myriad_httpc_backend, shotgun,

		_ExprIfMatching=request_via_shotgun( Method, Uri, Headers,
			MaybeBinContent, CertReqOptionMap, LEState ),

		% Expecting the myriad_httpc_backend define to be set to 'native_httpc'
		% instead of 'shotgun' here:
		%
		_ExprIfNotMatching=request_via_native_httpc( Method, Uri, Headers,
			MaybeBinContent, CertReqOptionMap, LEState ) ).



% @doc Queries the specified URI (GET or POST) with the shotgun library, and
% returns the corresponding result with an updated state.
%
-spec request_via_shotgun( 'get' | 'post', uri(), header_map(),
				maybe( bin_content() ), cert_req_option_map(), le_state() ) ->
						{ http_body(), le_state() }.
request_via_shotgun( Method, Uri, Headers, MaybeBinContent,
		CertReqOptionMap=#{ netopts := Netopts },
		LEState=#le_state{ tcp_connection_cache=TCPCache } ) ->

	UriStr = text_utils:ensure_string( Uri ),

	% uri_string:parse/1 will return the same type of strings as the one it is
	% given.
	%
	% Port may not be specified:
	UriMap = #{ scheme := UriSchemeStr, host := UriHost,
				path := UriPath } = uri_string:parse( UriStr ),

	UriProtoAtom = text_utils:string_to_atom( UriSchemeStr ),

	DefaultPort = case UriProtoAtom of

		http ->
			80;

		https ->
			443

	end,

	UriPort = maps:get( port, UriMap, DefaultPort ),

	cond_utils:if_defined( leec_debug_exchanges,
		trace_bridge:debug_fmt( "[~w] Preparing a (shotgun-based) ~p request "
								"to '~ts'.", [ self(), Method, Uri ] ) ),

	ContentHeaders = Headers#{ <<"content-type">> =>
									<<"application/jose+json">> },

	% We want to reuse connection if it already exists:
	{ Connection, NewTCPCache } =
		get_tcp_connection( UriProtoAtom, UriHost, UriPort, TCPCache ),

	ReqRes = case Method of

		get ->
			cond_utils:if_defined( leec_debug_exchanges,
				trace_bridge:debug_fmt( "[~w][client] GET request to URI "
					"'~ts', with following content headers:~n  ~p~n and "
					"network options ~p.",
					[ self(), UriStr, ContentHeaders, Netopts ] ) ),

			shotgun:get( Connection, UriPath, ContentHeaders, Netopts );

		post ->
			NillableContent = case MaybeBinContent of

				undefined ->
					nil;

				BinContent ->
					BinContent

			end,

			cond_utils:if_defined( leec_debug_exchanges,
				trace_bridge:debug_fmt( "[~w][client] POST request to URI "
					"'~ts', with following content headers:~n  ~p~n and "
					"content ~p, with network options ~p.",
					[ self(), UriStr, ContentHeaders, NillableContent,
					  Netopts ] ) ),

			shotgun:post( Connection, UriPath, ContentHeaders, NillableContent,
						  Netopts );

		_ ->
			throw( { invalid_method, Method, UriStr } )

	end,

	% Very useful yet quite verbose:
	cond_utils:if_defined( leec_debug_codec,
		trace_bridge:debug_fmt( "[~w][client] The '~ts' request to ~ts "
			"resulted in:~n  ~p", [ self(), Method, UriStr, ReqRes ] ) ),

	% Typically success results in ReqRes like:

	% {ok,#{headers =>
	%  [{<<"server">>,<<"nginx">>},
	%   {<<"date">>,<<"Mon, 12 Oct 2020 20:24:37 GMT">>},
	%   {<<"cache-control">>,<<"public, max-age=0, no-cache">>},
	%   {<<"link">>,
	%      <<"<https://acme-staging-v02.api.letsencrypt.org/directory>;rel=\"index\"">>},
	%   {<<"replay-nonce">>,
	%    <<"0004Rvtq_vk_FFeGDLHnbeb6ySKpkePx_frQeodOZ1byAPg">>},
	%   {<<"x-frame-options">>,<<"DENY">>},
	%   {<<"strict-transport-security">>,<<"max-age=604800">>}],
	%       status_code => 204}}

	case ReqRes of

		{ ok, Response=#{ headers := RHeaders } } ->

			% Updates response from its headers:
			Resp = Response#{
				nonce => proplists:get_value( <<"replay-nonce">>, RHeaders,
											  _Def=null ),
				location => proplists:get_value( <<"location">>, RHeaders,
												 _Def=null ) },

			JsonHttpBody = decode( CertReqOptionMap, Resp, LEState ),

			{ JsonHttpBody,
			  LEState#le_state{ tcp_connection_cache=NewTCPCache } };

		_ ->

			trace_bridge:error_fmt( "Request failed (via shotgun backend): "
				"method was ~p, URI was ~ts, result: ~p.~n Stacktrace: ~ts",
				[ Method, Uri, ReqRes, code_utils:interpret_stacktrace() ] ),

			throw( { request_failed, Method, UriStr, ReqRes } )

	end.



% @doc Queries the specified URI (GET or POST) with the Erlang-native httpc
% module (through Myriad support), and returns the corresponding result with an
% updated state.
%
-spec request_via_native_httpc( 'get' | 'post', uri(), header_map(),
				maybe( bin_content() ), cert_req_option_map(), le_state() ) ->
						{ http_body(), le_state() }.
request_via_native_httpc( Method, Uri, Headers, MaybeBinContent,
			CertReqOptionMap=#{ netopts := Netopts }, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges,
		trace_bridge:debug_fmt( "[~w] Preparing a (httpc-based) ~p request "
								"to '~ts'.", [ self(), Method, Uri ] ) ),

	% Readily compliant:
	HttpOpts = Netopts,

	ReqRes = case Method of

		get ->
			cond_utils:if_defined( leec_debug_exchanges,
				trace_bridge:debug_fmt( "[~w][client] GET request to URI "
					"'~ts', with following headers:~n  ~p~nand "
					"HTTP options: ~p.",
					[ self(), Uri, Headers, HttpOpts ] ) ),

			web_utils:get( Uri, Headers, HttpOpts );

		post ->
			MaybeContentType = case MaybeBinContent of

				undefined ->
					% Hopefully not already set in Headers:
					undefined;

				_ ->
					"application/jose+json"

			end,

			cond_utils:if_defined( leec_debug_exchanges,
				trace_bridge:debug_fmt( "[~w][client] POST request to URI "
					"'~ts', with following headers:~n  ~p~n"
					"HTTP options: ~p~nContent: ~p~nContent-type: ~ts.",
					[ self(), Uri, Headers, HttpOpts, MaybeBinContent,
					  MaybeContentType ] ) ),

			web_utils:post( Uri, Headers, HttpOpts, MaybeBinContent,
							MaybeContentType )

	end,

	% Very useful yet quite verbose:
	cond_utils:if_defined( leec_debug_codec,
		trace_bridge:debug_fmt( "[~w][client] The '~ts' request to ~ts "
			"resulted in:~n  ~p", [ self(), Method, Uri, ReqRes ] ) ),

	% Typically success results in ReqRes like:

	% {ok,#{headers =>
	%           [{<<"server">>,<<"nginx">>},
	%            {<<"date">>,<<"Mon, 12 Oct 2020 20:24:37 GMT">>},
	%            {<<"cache-control">>,<<"public, max-age=0, no-cache">>},
	%            {<<"link">>,
	%             <<"<https://acme-staging-v02.api.letsencrypt.org/directory>;rel=\"index\"">>},
	%            {<<"replay-nonce">>,
	%             <<"0004Rvtq_vk_FFeGDLHnbeb6ySKpkePx_frQeodOZ1byAPg">>},
	%            {<<"x-frame-options">>,<<"DENY">>},
	%            {<<"strict-transport-security">>,<<"max-age=604800">>}],
	%       status_code => 204}}

	case ReqRes of

		{ error, _ErrorReason } ->

			trace_bridge:error_fmt( "Request failed (via native httpc): "
				"method was ~p, URI was ~ts, result: ~p.~n Stacktrace: ~ts",
				[ Method, Uri, ReqRes, code_utils:interpret_stacktrace() ] ),

			throw( { request_failed, Method, Uri, ReqRes } );

		{ ReqStatusCode, ReqHeaders, ReqBody } ->

			BaseResponse = #{ status_code => ReqStatusCode,
							  headers => ReqHeaders,
							  body =>  ReqBody },

			% Updates response from its headers:
			Resp = BaseResponse#{

				nonce => table:get_value_with_defaults( <<"replay-nonce">>,
														_Def=null, ReqHeaders ),

				location => table:get_value_with_defaults( <<"location">>,
													_Def=null, ReqHeaders ) },

			JsonHttpBody = decode( CertReqOptionMap, Resp, LEState ),

			{ JsonHttpBody, LEState };

		_ ->

			trace_bridge:error_fmt( "Request failed (via native httpc): "
				"method was ~p, URI was ~ts, result: ~p.~n Stacktrace: ~ts",
				[ Method, Uri, ReqRes, code_utils:interpret_stacktrace() ] ),

			throw( { request_failed, Method, Uri, ReqRes } )

	end.



% @doc Called whenever an (ACME) request failed, whereas no suitable JSON body
% is available in the answer: reports error information and throws a
% corresponding exception.
%
-spec on_failed_request( http_status_code(), atom() ) -> no_return().
on_failed_request( StatusCode, StepAtom ) ->

	StatusStr = web_utils:interpret_http_status_code( StatusCode ),

	trace_bridge:critical_fmt( "An ACME request failed at the '~ts' step: ~ts.",
							   [ StepAtom, StatusStr ] ),

	throw( { request_failed, { status_code, StatusCode }, { reason, StatusStr },
				{ step, StepAtom } } ).



% @doc Called whenever an (ACME) request failed, whereas a suitable JSON body is
% available in the answer: reports error information and throws a corresponding
% exception.
%
-spec on_failed_request( http_status_code(), json_map_decoded(), atom() ) ->
								no_return().
on_failed_request( StatusCode, JsonMapBody, StepAtom ) ->

	StatusStr = web_utils:interpret_http_status_code( StatusCode ),

	Type = maps:get( _K= <<"type">>, JsonMapBody, _Def=unknown ),

	Detail = maps:get( <<"detail">>, JsonMapBody, unknown ),

	trace_bridge:critical_fmt( "An ACME request failed at the '~ts' step: ~ts, "
		"for the following reason: ~ts (error type: ~ts).",
		[ StepAtom, StatusStr, Detail, Type ] ),

	Reason = case Detail of

		unknown ->
			StatusStr;

		_ ->
			Detail

	end,

	throw( { request_failed, { status_code, StatusCode },
				{ reason, text_utils:ensure_string( Reason ) },
				{ step, StepAtom } } ).




%%
%% Public functions.
%%


% @doc Returns a directory map listing all ACME protocol URLs.
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1].
%
-spec get_directory_map( environment(), cert_req_option_map(), le_state() ) ->
							{ leec:directory_map(), le_state() }.
get_directory_map( Env, CertReqOptionMap, LEState ) ->

	DirUri = case Env of

		staging ->
			?staging_api_url;

		prod ->
			?default_api_url

	end,

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Getting directory map at ~ts.", [ self(), DirUri ] ) ),

	{ #{ json := DirectoryMap, status_code := StatusCode }, NewLEState } =
		request( _Method=get, DirUri, _Headers=#{}, _MaybeBinContent=undefined,
				 CertReqOptionMap#{ json => true }, LEState ),

	case StatusCode of

		_Success=200 ->
			ok;

		_ ->
			on_failed_request( StatusCode, DirectoryMap, get_directory_map )

	end,

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Obtained directory map:~n~p", [ self(), DirectoryMap ] ) ),

	{ DirectoryMap, NewLEState }.



% @doc Gets and returns a fresh nonce by using the corresponding URI.
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2].
%
-spec get_nonce( directory_map(), cert_req_option_map(), le_state() ) ->
					{ nonce(), le_state() }.
get_nonce( _DirMap=#{ <<"newNonce">> := Uri }, CertReqOptionMap, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges,
		trace_bridge:debug_fmt( "[~w] Getting new nonce from ~ts.",
								[ self(), Uri ] ) ),

	{ #{ nonce := Nonce, status_code := StatusCode }, NewLEState }  =
		request( _Method=get, Uri, _Headers=#{}, _MaybeBinContent=undefined,
				 CertReqOptionMap, LEState ),

	case StatusCode of

		_NoContent=204 ->
			ok;

		_ ->
			on_failed_request( StatusCode, get_nonce )

	end,

	cond_utils:if_defined( leec_debug_exchanges,
		trace_bridge:debug_fmt( "[~w] New nonce is: ~p.", [ self(), Nonce ] ) ),

	{ Nonce, NewLEState }.



% @doc Requests an account obtained (indirectly) for specified private key.
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.1].
%
% This is either a new account or one that was already created by this FSM.
%
% Returns {Response, Location, Nonce}, where:
%
% - Response is json (decoded as map)
%
% - Location is the URL corresponding to the created ACME account
%
% - Nonce is a new valid replay-nonce
%
-spec get_acme_account( directory_map(), tls_private_key(), jws(),
						cert_req_option_map(), le_state() ) ->
			{ { json_map_decoded(), bin_uri(), nonce() }, le_state() }.
get_acme_account( _DirMap=#{ <<"newAccount">> := Uri }, PrivKey, Jws,
				  CertReqOptionMap, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges,
		trace_bridge:debug_fmt( "[~w] Requesting a new account from ~ts.",
								[ self(), Uri ] ) ),

	% Terms of service should not be automatically agreed.
	%
	% Example of contact: "mailto:cert-admin@foobar.org".
	%
	Payload = #{ termsOfServiceAgreed => true, contact => [] },

	ReqB64 = leec_jws:encode( PrivKey, Jws#jws{ url=Uri }, Payload, LEState ),

	{ #{ json := RespMap, location := LocationUri, nonce := NewNonce,
	   status_code := StatusCode }, NewLEState } = request( _Method=post, Uri,
			_Headers=#{}, _MaybeBinContent=ReqB64,
			CertReqOptionMap#{ json => true }, LEState ),

	case StatusCode of

		_CreatedCode=201 ->
			cond_utils:if_defined( leec_debug_exchanges,
				trace_bridge:debug_fmt( "[~w] Account created.", [ self() ] ),
				ok );

		% Happens, should this account already exist (in using the same LEEC FSM
		% for more than one certificate operation, or re-using a pre-existing
		% account from the start):
		%
		_Success=200 ->
			cond_utils:if_defined( leec_debug_exchanges,
				trace_bridge:debug_fmt( "[~w] Account connected to "
					"(was already created).", [ self() ] ),
				ok );

		_ ->
			on_failed_request( StatusCode, RespMap, get_acme_account )

	end,

	cond_utils:if_defined( leec_debug_exchanges,
		trace_bridge:debug_fmt( "[~w] Account location URI is '~ts', "
			"JSON response is :~n  ~p", [ self(), LocationUri, RespMap ] ) ),

	{ { RespMap, LocationUri, NewNonce }, NewLEState }.



% @doc Requests (orders from ACME) a new certificate (of DNS type).
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4].
%
% Returns {Response, Location, Nonce}, where:
%
% - Response is json (decoded as map)
%
% - Location is the URL corresponding to the created ACME account
%
% - Nonce is a new valid replay-nonce
%
-spec request_new_certificate( directory_map(), [ bin_domain() ],
		tls_private_key(), jws(), cert_req_option_map(), le_state() ) ->
				{ { json_map_decoded(), bin_uri(), nonce() }, le_state() }.
request_new_certificate( _DirMap=#{ <<"newOrder">> := OrderUri }, BinDomains,
						 PrivKey, AccountJws, CertReqOptionMap, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Requesting a new certificate from ~ts for:~n  ~p",
		[ self(), OrderUri, BinDomains ] ) ),

	Idns = [ #{ type => dns, value => BinDomain } || BinDomain <- BinDomains ],

	IdPayload = #{ identifiers => Idns },

	Req = leec_jws:encode( PrivKey, AccountJws#jws{ url=OrderUri },
						   _Content=IdPayload, LEState ),

	{ #{ json := OrderJsonMap, location := LocationUri,
		 nonce := Nonce, status_code := StatusCode }, NewLEState } =
			request( _Method=post, OrderUri, _Headers=#{}, _MaybeBinContent=Req,
					 CertReqOptionMap#{ json => true }, LEState ),

	case StatusCode of

		_CreatedCode=201 ->
			ok;

		_ ->
			on_failed_request( StatusCode, OrderJsonMap,
							   request_new_certificate )

	end,

	cond_utils:if_defined( leec_debug_codec, trace_bridge:debug_fmt(
		"[~w] Obtained from order URI '~ts' the "
		"location '~ts' and following JSON:~n  ~p",
		[ self(), OrderUri, LocationUri, OrderJsonMap ] ) ),

	%trace_bridge:debug_fmt( "[~w] Obtained from order URI '~ts' the "
	%	"location '~ts'.", [ self(), OrderUri, LocationUri ] ),

	% OrderJsonMap like:
	%
	% #{<<"authorizations">> =>
	%     [<<"https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/132509381">>],
	%	<<"expires">> => <<"2020-10-21T10:08:04.97820359Z">>,
	%   <<"finalize">> =>
	%	  <<"https://acme-staging-v02.api.letsencrypt.org/acme/finalize/16110969/166839186">>,
	%   <<"identifiers">> =>
	%		[#{<<"type">> => <<"dns">>,<<"value">> => <<"foo.bar.org">>}],
	%   <<"status">> => <<"pending">>}

	{ { OrderJsonMap, LocationUri, Nonce }, NewLEState }.



% @doc Orders a new certificate from the ACME server.
-spec get_order( bin_uri(), bin_key(), jws(), cert_req_option_map(),
				 le_state() ) ->
		{ { json_map_decoded(), bin_uri(), nonce() }, le_state() }.
get_order( Uri, Key, Jws, CertReqOptionMap, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Getting order at ~ts.", [ self(), Uri ] ) ),

	% POST-as-GET implies no payload:

	Req = leec_jws:encode( Key, Jws#jws{ url=Uri }, _Content=undefined,
						   LEState ),

	{ #{ json := RespMap, location := Location, nonce := Nonce,
		 status_code := StatusCode }, NewLEState } =
		request( _Method=post, Uri, _Headers=#{}, _MaybeBinContent=Req,
				 CertReqOptionMap#{ json=> true }, LEState ),

	case StatusCode of

		_Success=200 ->
			ok;

		_ ->
			on_failed_request( StatusCode, RespMap, get_order )

	end,

	{ { RespMap, Location, Nonce }, NewLEState }.



% @doc Requests authorization for given identifier.
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.1].
%
% Returns {Response, Location, Nonce}, where:
%  - Response is json (decoded as map)
%  - Location is create account url
%  - Nonce is a new valid replay-nonce
%
-spec request_authorization( bin_uri(), tls_private_key(), jws(),
							 cert_req_option_map(), le_state() ) ->
		{ { json_map_decoded(), bin_uri(), nonce() }, le_state() }.
request_authorization( AuthUri, PrivKey, Jws, CertReqOptionMap, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Requesting authorization from ~ts.", [ self(), AuthUri ] ) ),

	% POST-as-GET implies no payload:
	B64AuthReq = leec_jws:encode( PrivKey, Jws#jws{ url=AuthUri },
								  _Content=undefined, LEState ),

	{ #{ json := RespMap, location := LocationUri, nonce := Nonce,
	   status_code := StatusCode }, NewLEState } = request( _Method=post,
			AuthUri, _Headers=#{}, _MaybeBinContent=B64AuthReq,
			CertReqOptionMap#{ json=> true }, LEState ),

	case StatusCode of

		_Success=200 ->
			ok;

		_ ->
			on_failed_request( StatusCode, RespMap, request_authorization )

	end,

	{ { RespMap, LocationUri, Nonce }, NewLEState }.



% @doc Notifies the ACME server that we are ready for challenge validation.
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1].
%
% Returns {Response, Location, Nonce}, where:
%
%  - Response is json (decoded as map)
%
%  - Location is create account url
%
%  - Nonce is a new valid replay-nonce
%
%
-spec notify_ready_for_challenge( challenge(), bin_key(), jws(),
								  cert_req_option_map(), le_state() ) ->
			{ { json_map_decoded(), bin_uri(), nonce() }, le_state() }.
notify_ready_for_challenge( _Challenge=#{ <<"url">> := Uri }, PrivKey, Jws,
							CertReqOptionMap, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Notifying the ACME server that our agent is "
		"ready for challenge validation at ~ts.", [ self(), Uri ] ) ),

	% POST-as-GET implies no payload:
	Req = leec_jws:encode( PrivKey, Jws#jws{ url=Uri }, _Content=#{}, LEState ),

	{ #{ json := RespMap, location := Location, nonce := Nonce,
	  status_code := StatusCode }, NewLEState } = request( _Method=post, Uri,
		_Headers=#{}, _MaybeBinContent=Req, CertReqOptionMap#{ json => true },
														   LEState ),

	case StatusCode of

		_Success=200 ->
			ok;

		_ ->
			on_failed_request( StatusCode, RespMap, notify_ready_for_challenge )

	end,

	{ { RespMap, Location, Nonce }, NewLEState }.



% @doc Finalizes the order once a challenge has been validated.
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4].
%
-spec finalize_order( order_map(), bin_csr_key(), tls_private_key(), jws(),
	cert_req_option_map(), le_state() ) ->
		{ { json_map_decoded(), bin_uri(), nonce() }, le_state() }.
finalize_order( _OrderDirMap=#{ <<"finalize">> := FinUri }, Csr, PrivKey, Jws,
				CertReqOptionMap, LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Finalizing order at ~ts.", [ self(), FinUri ] ) ),

	Payload = #{ csr => Csr },

	JWSBody = leec_jws:encode( PrivKey, Jws#jws{ url=FinUri }, Payload,
							   LEState ),

	{ #{ json := FinOrderDirMap, location := BinLocUri, nonce := Nonce,
	   status_code := StatusCode }, NewLEState } = request( _Method=post,
			FinUri, _Headers=#{}, _MaybeBinContent=JWSBody,
			CertReqOptionMap#{ json => true }, LEState ),

	case StatusCode of

		_Success=200 ->
			ok;

		% If trying to progress whereas a past operation failed:
		Forbidden=403 ->
			trace_bridge:error_fmt( "Unable to finalize order (~ts). "
				"Possibly a past operation failed.",
				[ web_utils:interpret_http_status_code( Forbidden ) ] ),
			throw( { forbidden_status_code, StatusCode, finalize_order } );

		_ ->
			% If code 403 ("forbidden"), possibly a past operation failed.
			on_failed_request( StatusCode, FinOrderDirMap, finalize_order )

	end,

	{ { FinOrderDirMap, BinLocUri, Nonce }, NewLEState }.



% @doc Downloads certificate for finalized order and returns itself.
%
% Refer to [https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2].
%
-spec get_certificate( order_map(), tls_private_key(), jws(),
					   cert_req_option_map(), le_state() ) ->
		  { { bin_certificate(), nonce() }, le_state() }.
get_certificate( #{ <<"certificate">> := Uri }, Key, Jws, CertReqOptionMap,
				 LEState ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Downloading certificate at ~ts.", [ self(), Uri ] ) ),

	% POST-as-GET implies no payload:
	Req = leec_jws:encode( Key, Jws#jws{ url=Uri }, _Content=undefined,
						   LEState ),

	{ #{ body := BinCert, nonce := NewNonce, status_code := StatusCode  },
	  NewLEState } = request( _Method=post, Uri, _Headers=#{},
							  _MaybeBinContent=Req, CertReqOptionMap, LEState ),

	case StatusCode of

		_Success=200 ->
			ok;

		_ ->
			on_failed_request( StatusCode, get_certificate )

	end,

	{ { BinCert, NewNonce }, NewLEState }.
