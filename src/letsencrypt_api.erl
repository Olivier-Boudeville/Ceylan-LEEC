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

-module(letsencrypt_api).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([ get_directory_map/2, get_nonce/2, create_acme_account/4,
		  request_new_certificate/5, get_order/4, request_authorization/4,
		  notify_ready_for_challenge/4, finalize_order/5, get_certificate/4,
		  binary_to_status/1,
		  get_tcp_connection/3, close_tcp_connections/0 ]).


-type json_http_body() :: map().

-type header_map() :: map().

-type bin_content() :: binary().

-type option_map() :: letsencrypt:option_map().

% Not 'prod':
-type environment() :: 'default' | 'staging'.

% For the records introduced:
-include("letsencrypt.hrl").

% Not involving Myriad's parse transform here:
-type maybe( T ) :: T | 'undefined'.

% Silenced, so that the same code can be compiled with or without Myriad's parse
% transform:
%
-export_type([ maybe/1 ]).


% Shorthands:
-type challenge() :: letsencrypt:challenge().
-type uri() :: letsencrypt:uri().
-type tls_private_key() :: letsencrypt:tls_private_key().
-type bin_domain() :: letsencrypt:bin_domain().
-type bin_key() :: letsencrypt:bin_key().
-type bin_csr_key() :: letsencrypt:bin_csr_key().
-type directory_map() :: letsencrypt:directory_map().
-type bin_uri() :: letsencrypt:bin_uri().
-type json_map_decoded() :: letsencrypt:json_map_decoded().
-type nonce() :: letsencrypt:nonce().
-type jws() :: letsencrypt:jws().
-type order_map() :: letsencrypt:order_map().
-type bin_certificate() :: letsencrypt:bin_certificate().


-ifdef(TEST).
	-define( staging_api_url, <<"https://127.0.0.1:14000/dir">> ).
	-define( default_api_url, <<"">> ).
-else.

	-define( staging_api_url,
			 <<"https://acme-staging-v02.api.letsencrypt.org/directory">> ).

	-define( default_api_url,
			 <<"https://acme-v02.api.letsencrypt.org/directory">> ).

-endif.

-ifdef(LEEC_DEBUG).
	-define( debug( Fmt, Args ), trace_bridge:debug_fmt( Fmt, Args ) ).
-else.
	-define( debug( Fmt, Args ), ok ).
-endif.


% Name of the ETS table storing current connections:
-define( connection_table, leec_connections ).


% Returns the status corresponding to specified binary.
-spec binary_to_status( binary() ) -> letsencrypt:status().
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



%% PRIVATE


% Returns a suitable TCP connection.
%
% If a connection to the given Host:Port is already opened, returns it,
% otherwise opens a new connection.
%
% Opened connections are stored in the ?connection_table ETS table.
%
% TODO: checks connection is still alive (ping?)
%
% Note: for long-living processes (ex: up to 90 days can elapse between two
% certification generations for a given domain), it is certainly safer to reset
% that connection cache.
%
-spec get_tcp_connection( net_utils:protocol_type(),
		net_utils:string_host_name(), net_utils:tcp_port() ) ->
		  shotgun:connection().
get_tcp_connection( Proto, Host, Port ) ->

	case ets:info( ?connection_table ) of

		% Table does not exist, let's create it:
		undefined ->
			ets:new( ?connection_table, [ set, named_table ] );

		_ ->
			ok
	end,

	ConnectTriplet = { Proto, Host, Port },

	case ets:lookup( ?connection_table, ConnectTriplet ) of

		% Not found:
		[] ->
			trace_bridge:debug_fmt( "[~w] Opening a connection to ~s:~B, "
				"with the '~s' scheme.", [ self(), Host, Port, Proto ] ),

			Conn = case shotgun:open( Host, Port, Proto ) of

				{ ok, Connection } ->
				   Connection;

				{ error, gun_open_failed } ->
				   throw( { gun_open_failed, Host, Port, Proto } );

				{ error, Error } ->
				   throw( { gun_open_failed, Error, Host, Port, Proto } )

		   end,

			ets:insert( ?connection_table, { ConnectTriplet, Conn } ),
			trace_bridge:trace_fmt( "Connection ~p cached.", [ Conn ] ),
			Conn;

		[ { _ConnectTriplet, Conn } ] ->
			trace_bridge:debug_fmt( "[~w] Reusing connection to ~s:~B, "
				"with the '~s' scheme: ~w.",
				[ self(), Host, Port, Proto, Conn ] ),
			Conn

	end.



% Closes all pending (cached) TCP connections.
-spec close_tcp_connections() -> basic_utils:void().
close_tcp_connections() ->

	Table = ?connection_table,

	case ets:info( Table ) of

		undefined ->
			ok;

		_ ->
			% Not testing any returned close error, needing to resist them:
			[ shotgun:close( pair:second( Conn ) )
			  || Conn <- ets:tab2list( Table ) ],
			ets:delete( Table )

	end.



% Decodes http body as JSON if requested in options, or returns it as is.
%
% Returns that response, with added JSON structure if required.
%
-spec decode( OptionMap :: option_map(), Response :: map() ) ->
					json_http_body().
decode( _OptionMap=#{ json := true }, Response=#{ body := Body } ) ->

	%trace_bridge:debug_fmt( "Decoding from JSON following body:~n~p",
	%						[ Body ] ),

	Payload = json_utils:from_json( Body ),

	%trace_bridge:debug_fmt( "Payload decoded from JSON:~n  ~p", [ Payload ] ),

	Response#{ json => Payload };

decode( _OptionMap, Response ) ->
	%trace_bridge:debug_fmt( "Not requested to decode from JSON following "
	%						"response:~n~p", [ Response ] ),
	Response.



% Queries an URI (GET or POST) and returns results.
%
% Returns:
%	{ok, #{status_coe, body, headers}}: query succeed
%	{error, invalid_method}           : method must be either 'get' or 'post'
%   {error, term()}                   : query failed
%
% TODO: is 'application/jose+json' content type always required?
%       (check ACME documentation)
%
-spec request( 'get' | 'post', uri(), header_map(),
			   maybe( bin_content() ), option_map() ) -> shotgun:result() .
request( Method, Uri, Headers, MaybeBinContent,
		 OptionMap=#{ netopts := Netopts } ) ->

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

	ContentHeaders = Headers#{ <<"content-type">> =>
								   <<"application/jose+json">> },

	% We want to reuse connection if it already exists:
	Connection = get_tcp_connection( UriProtoAtom, UriHost, UriPort ),

	ReqRes = case Method of

		get ->
			shotgun:get( Connection, UriPath, ContentHeaders, Netopts );

		post ->
			NillableContent = case MaybeBinContent of

				undefined ->
					nil;

				BinContent ->
					BinContent

			end,

			shotgun:post( Connection, UriPath, ContentHeaders, NillableContent,
						  Netopts );

		_ ->
			throw( { invalid_method, Method, UriStr } )

	end,

	% Very useful yet quite verbose:
	%trace_bridge:debug_fmt( "[~w] The '~s' request to ~s resulted in:~n~p",
	%						[ self(), Method, UriStr, ReqRes ] ),

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

		{ ok, Response=#{ headers := RHeaders } } ->
			% Updates response from its headers:
			Resp = Response#{
				nonce => proplists:get_value( <<"replay-nonce">>, RHeaders,
											  _Def=null ),
				location => proplists:get_value( <<"location">>, RHeaders,
												 _Def=null )
			},
			decode( OptionMap, Resp );

		_ ->
			throw( { unexpected_request_answer, Method, UriStr, ReqRes } )

	end.



%%
%% Public functions.
%%


% Returns a directory map listing all ACME protocol URLs (see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1).
%
-spec get_directory_map( environment(), option_map() ) ->
							   letsencrypt:directory_map().
get_directory_map( Env, OptionMap ) ->

	DirUri = case Env of

		staging ->
			?staging_api_url;

		prod ->
			?default_api_url

	end,

	trace_bridge:debug_fmt( "[~w] Getting directory map at ~s.",
							[ self(), DirUri ] ),

	#{ json := DirectoryMap, status_code := StatusCode } = request( _Method=get,
		DirUri, _Headers=#{}, _MaybeBinContent=undefined,
		OptionMap#{ json => true } ),

	case StatusCode of

		200 ->
			ok;

		_ ->
			throw( { unexpected_status_code, StatusCode, get_directory_map } )

	end,

	trace_bridge:debug_fmt( "[~w] Obtained directory map:~n~p",
							[ self(), DirectoryMap ] ),

	DirectoryMap.



% Gets and returns a fresh nonce by using the correspoding URI (see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2).
%
-spec get_nonce( directory_map(), option_map() ) -> nonce().
get_nonce( _DirMap=#{ <<"newNonce">> := Uri }, OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Getting new nonce from ~s.", [ self(), Uri ] ),

	% Status code: 204 (No content):
	#{ nonce := Nonce, status_code := StatusCode } = request( _Method=get, Uri,
				_Headers=#{}, _MaybeBinContent=undefined, OptionMap ),

	case StatusCode of

		204 ->
			ok;

		_ ->
			throw( { unexpected_status_code, StatusCode, get_nonce } )

	end,

	trace_bridge:debug_fmt( "[~w] New nonce is: ~p.", [ self(), Nonce ] ),

	Nonce.



% Requests an account obtained (indirectly) for specified private key, see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.1.
%
% This is either a new account or one that was already created by this FSM.
%
% Returns {Response, Location, Nonce}, where:
% - Response is json (decoded as map)
% - Location is the URL corresponding to the created ACME account
% - Nonce is a new valid replay-nonce
%
-spec create_acme_account( directory_map(), tls_private_key(), jws(),
			   option_map() ) -> { json_map_decoded(), bin_uri(), nonce() }.
create_acme_account( _DirMap=#{ <<"newAccount">> := Uri }, PrivKey, Jws,
					 OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Requesting a new account from ~s.",
							[ self(), Uri ] ),

	% Terms of service should not be automatically agreed:
	Payload = #{ termsOfServiceAgreed => true,
				 contact => [] },

	ReqB64 = letsencrypt_jws:encode( PrivKey, Jws#jws{ url=Uri }, Payload ),

	#{ json := Resp, location := LocationUri, nonce := NewNonce,
	   status_code := StatusCode } = request( _Method=post, Uri, _Headers=#{},
			_MaybeBinContent=ReqB64, OptionMap#{ json => true } ),

	case StatusCode of

		_CreatedCode=201 ->
			ok;

		% Happens should this account already exist (in using the same LEEC FSM
		% for more than one certificate operation):
		%
		_Success=200 ->
			ok;
		_ ->
			throw( { unexpected_status_code, StatusCode, create_acme_account } )

	end,

	trace_bridge:debug_fmt( "[~w] Account location URI is '~s', "
		"JSON response is :~n  ~p", [ self(), LocationUri, Resp ] ),

	{ Resp, LocationUri, NewNonce }.



% Requests (orders from ACME) a new (DNS) certificate, see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.
%
% Returns {Response, Location, Nonce}, where:
% - Response is json (decoded as map)
% - Location is the URL corresponding to the created ACME account
% - Nonce is a new valid replay-nonce
%
-spec request_new_certificate( directory_map(), [ bin_domain() ],
		tls_private_key(), jws(), option_map() ) ->
								 { json_map_decoded(), bin_uri(), nonce() }.
request_new_certificate( _DirMap=#{ <<"newOrder">> := OrderUri }, BinDomains,
						 PrivKey, AccountJws, OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Requesting a new certificate from ~s for ~p.",
							[ self(), OrderUri, BinDomains ] ),

	Idns = [ #{ type => dns, value => BinDomain } || BinDomain <- BinDomains ],

	IdPayload = #{ identifiers => Idns },

	Req = letsencrypt_jws:encode( PrivKey, AccountJws#jws{ url=OrderUri },
								  _Content=IdPayload ),

	#{ json := OrderJsonMap, location := LocationUri, nonce := Nonce,
	   status_code := StatusCode } = request( _Method=post, OrderUri,
		_Headers=#{}, _MaybeBinContent=Req, OptionMap#{ json => true } ),

	case StatusCode of

		_CreatedCode=201 ->
			ok;

		_ ->
			throw( { unexpected_status_code, StatusCode,
					 request_new_certificate } )

	end,

	trace_bridge:debug_fmt( "[~w] Obtained from order URI '~s' the "
		"location '~s' and following JSON:~n  ~p",
		[ self(), OrderUri, LocationUri, OrderJsonMap ] ),

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

	{ OrderJsonMap, LocationUri, Nonce }.



% Returns order state.
-spec get_order( bin_uri(), bin_key(), jws(), option_map() ) ->
		  { json_map_decoded(), bin_uri(), nonce() }.
get_order( Uri, Key, Jws, OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Getting order at ~s.", [ self(), Uri ] ),

	% POST-as-GET implies no payload:

	Req = letsencrypt_jws:encode( Key, Jws#jws{ url=Uri }, _Content=undefined ),

	#{ json := Resp, location := Location, nonce := Nonce } =
		request( _Method=post, Uri, _Headers=#{}, _MaybeBinContent=Req,
				 OptionMap#{ json=> true } ),

	{ Resp, Location, Nonce }.



% Requests authorization for given identifier, see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.1.
%
% Returns {Response, Location, Nonce}, where:
%		- Response is json (decoded as map)
%		- Location is create account url
%		- Nonce is a new valid replay-nonce
%
-spec request_authorization( bin_uri(), tls_private_key(), jws(),
			 option_map() ) -> { json_map_decoded(), bin_uri(), nonce() }.
request_authorization( AuthUri, PrivKey, Jws, OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Requesting authorization from ~s.",
							[ self(), AuthUri ] ),

	% POST-as-GET implies no payload:
	B64AuthReq = letsencrypt_jws:encode( PrivKey, Jws#jws{ url=AuthUri },
										 _Content=undefined ),

	#{ json := Resp, location := LocationUri, nonce := Nonce,
	   status_code := StatusCode } = request( _Method=post, AuthUri,
		_Headers=#{}, _MaybeBinContent=B64AuthReq, OptionMap#{ json=> true } ),

	case StatusCode of

		200 ->
			ok;

		_ ->
			throw( { unexpected_status_code, StatusCode,
					 request_authorization } )

	end,

	{ Resp, LocationUri, Nonce }.



% Notifies the ACME server that we are ready for challenge validation (see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
%
% Returns {Response, Location, Nonce}, where:
%		- Response is json (decoded as map)
%		- Location is create account url
%		- Nonce is a new valid replay-nonce
%
-spec notify_ready_for_challenge( challenge(), bin_key(), jws(),
			  option_map() ) -> { json_map_decoded(), bin_uri(), nonce() }.
notify_ready_for_challenge( _Challenge=#{ <<"url">> := Uri }, PrivKey, Jws,
							OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Notifying the ACME server that our agent is "
		"ready for challenge validation at ~s.", [ self(), Uri ] ),

	% POST-as-GET implies no payload:
	Req = letsencrypt_jws:encode( PrivKey, Jws#jws{ url=Uri }, _Content=#{} ),

	#{ json := Resp, location := Location, nonce := Nonce,
	   status_code := StatusCode } = request( _Method=post, Uri, _Headers=#{},
			_MaybeBinContent=Req, OptionMap#{ json => true } ),

	case StatusCode of

		200 ->
			ok;

		_ ->
			throw( { unexpected_status_code, StatusCode,
					 notify_ready_for_challenge } )

	end,

	{ Resp, Location, Nonce }.



% Finalizes order once a challenge has been validated, see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.
%
-spec finalize_order( order_map(), bin_csr_key(), tls_private_key(), jws(),
			  option_map() ) -> { json_map_decoded(), bin_uri(), nonce() }.
finalize_order( _OrderDirMap=#{ <<"finalize">> := FinUri }, Csr, PrivKey, Jws,
				OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Finalizing order at ~s.", [ self(), FinUri ] ),

	Payload = #{ csr => Csr },

	JWSBody = letsencrypt_jws:encode( PrivKey, Jws#jws{ url=FinUri }, Payload ),

	#{ json := FinOrderDirMap, location := BinLocUri, nonce := Nonce,
	   status_code := StatusCode } = request( _Method=post, FinUri,
		  _Headers=#{}, _MaybeBinContent=JWSBody, OptionMap#{ json => true } ),

	case StatusCode of

		200 ->
			ok;

		_ ->
			throw( { unexpected_status_code, StatusCode, finalize_order } )

	end,

	{ FinOrderDirMap, BinLocUri, Nonce }.



% Downloads certificate for finalized order (see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2) and returns it.
%
-spec get_certificate( order_map(), tls_private_key(), jws(), option_map() ) ->
		  { bin_certificate(), nonce() }.
get_certificate( #{ <<"certificate">> := Uri }, Key, Jws, OptionMap ) ->

	trace_bridge:debug_fmt( "[~w] Downloading certificate at ~s.",
							[ self(), Uri ] ),

	% POST-as-GET implies no payload:
	Req = letsencrypt_jws:encode( Key, Jws#jws{ url=Uri }, _Content=undefined ),

	#{ body := BinCert, nonce := NewNonce, status_code := StatusCode  } =
		request( _Method=post, Uri, _Headers=#{}, _MaybeBinContent=Req,
				 OptionMap ),

	case StatusCode of

		200 ->
			ok;

		_ ->
			throw( { unexpected_status_code, StatusCode, get_certificate } )

	end,

	{ BinCert, NewNonce }.
