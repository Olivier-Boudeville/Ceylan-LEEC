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

-export([ get_directory_map/2, get_nonce/2, get_account/4,
		  request_order/5, get_order/4, request_authorization/4,
		  notify_ready_for_challenge/4, finalize_order/5, get_certificate/4,
		  binary_to_status/1 ]).


-type json_http_body() :: map().

-type header_map() :: map().

-type bin_content() :: binary().

-type option_map() :: letsencrypt:option_map().

% Not 'prod':
-type environment() :: 'default' | 'staging'.

% For the records introduced:
-include_lib("letsencrypt/include/letsencrypt.hrl").


% Shorthands:

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
	-define( debug( Fmt, Args ), trace_utils:debug_fmt( Fmt, Args ) ).
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
	trace_utils:error_fmt( "Invalid status: '~p'.", [ InvalidBinStatus ] ),
	throw( { invalid_status, InvalidBinStatus } ).



%% PRIVATE


% Returns a suitable TCP connection.
%
% If a connection to the given Host:Port is already opened, returns it, either
% opens a new connection.
%
% Opened connections are stored in the ?connection_table ETS table.
%
% TODO: checks connection is still alive (ping?)
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
			trace_utils:debug_fmt( "Opening connection to ~s:~B, with the "
				"'~s' scheme.", [ Host, Port, Proto ] ),

			Conn = case shotgun:open( Host, Port, Proto ) of

				{ ok, Connection } ->
				   Connection;

				{ error, gun_open_failed } ->
				   throw( { gun_open_failed, Host, Port, Proto } )

		   end,

			ets:insert( ?connection_table, { ConnectTriplet, Conn } ),
			Conn;

		[ { _ConnectTriplet, Conn } ] ->
			Conn

	end.



% Decodes http body as JSON if requested in options, or returns it as is.
%
% Returns {ok, Result} with added JSON structure if required.
%
-spec decode( OptionMap :: option_map(), Response :: map() ) ->
					json_http_body().
decode( _OptionMap=#{ json := true }, Response=#{ body := Body } ) ->
	Payload = json_utils:from_json( Body ),
	Response#{ json => Payload };

decode( _OptionMap, Response ) ->
	Response.



% Query an URI (GET or POST) and returns results:
% returns:
%	{ok, #{status_coe, body, headers}}: query succeed
%	{error, invalid_method}           : Method MUST be either 'get' or 'post'
%   {error, term()}                   : query failed
%
% TODO: is 'application/jose+json' content type always required?
%       (check ACME documentation)
%
-spec request( 'get' | 'post', uri(), header_map(), maybe( bin_content() ),
		   option_map() ) -> shotgun:result() | basic_utils:base_status().
request( Method, Uri, Headers, MaybeBinContent,
		 OptionMap=#{ netopts := Netopts } ) ->

	% Port may not be specified:
	UriMap = #{ scheme := UriSchemeStr, host := UriHost, path := UriPath } =
		uri_string:parse( Uri ),

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
			{ error, { invalid_method, Method } }

	end,

	trace_utils:debug_fmt( "[~w] ~s request to ~p at ~p "
		"resulted in: ~p.", [ self(), Method, Uri, UriMap, ReqRes ] ),

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
			ReqRes

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

	Uri = case Env of

		staging ->
			?staging_api_url;

		prod ->
			?default_api_url

	end,

	trace_utils:debug_fmt( "[~w] Getting directory map at ~s.",
						   [ self(), Uri ] ),

	{ ok, #{ json := DirectoryMap } } = request( _Method=get, Uri, _Headers=#{},
		 _MaybeBinContent=undefined, OptionMap#{ json => true } ),

	DirectoryMap.



% Gets and returns a fresh nonce by using the correspoding URI (see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2).
%
-spec get_nonce( directory_map(), option_map() ) -> nonce().
get_nonce( _DirMap=#{ <<"newNonce">> := Uri }, OptionMap ) ->

	trace_utils:debug_fmt( "[~w] Getting new nonce at ~s.", [ self(), Uri ] ),

	{ ok, #{ nonce := Nonce } } = request( _Method=get, Uri, _Headers=#{},
									_MaybeBinContent=undefined, OptionMap ),
	Nonce.



% Requests a new account, see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.1.
%
% Returns {Response, Location, Nonce}, where:
%		- Response is json (decoded as map)
%		- Location is create account url
%		- Nonce is a new valid replay-nonce
%
% TODO: checks 201 Created response
%
-spec get_account( directory_map(), tls_private_key(), jws(), option_map() ) ->
		  { json_map_decoded(), bin_uri(), nonce() }.
get_account( _DirMap=#{ <<"newAccount">> := Uri }, PrivKey, Jws, OptionMap ) ->

	trace_utils:debug_fmt( "[~w] Requesting a new account at ~s.",
						   [ self(), Uri ] ),

	% Terms of service should not be automatically agreed:
	Payload = #{ termsOfServiceAgreed => true,
				 contact => [] },

	ReqB64 = letsencrypt_jws:encode( PrivKey, Jws#jws{ url=Uri }, Payload ),

	{ ok, #{ json := Resp, location := LocationUri, nonce := NewNonce } } =
		request( _Method=post, Uri, _Headers=#{}, _MaybeBinContent=ReqB64,
				 OptionMap#{ json => true } ),

	{ Resp, LocationUri, NewNonce }.



% Requests a new order, see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.
%
% Returns {Response, Location, Nonce}, where:
%		- Response is json (decoded as map)
%		- Location is create account URI
%		- Nonce is a new valid replay-nonce
%
% TODO: support multiple domains
%		checks 201 created
%
-spec request_order( directory_map(), [ bin_domain() ], tls_private_key(),
		 jws(), option_map() ) -> { json_map_decoded(), bin_uri(), nonce() }.
request_order( _DirMap=#{ <<"newOrder">> := Uri }, BinDomains, PrivKey, Jws,
			   OptionMap ) ->

	trace_utils:debug_fmt( "[~w] Requesting a new order at ~s.",
						   [ self(), Uri ] ),

	Idns = [ #{ type => dns, value => BinDomain } || BinDomain <- BinDomains ],

	Payload = #{ identifiers => Idns },

	Req = letsencrypt_jws:encode( PrivKey, Jws#jws{ url=Uri },
								  _Content=Payload ),

	{ok, #{ json := OrderJsonMap, location := LocationUri, nonce := Nonce } } =
		request( _Method=post, Uri, _Headers=#{}, _MaybeBinContent=Req,
				 OptionMap#{ json => true } ),

	{ OrderJsonMap, LocationUri, Nonce }.



% Returns order state.
-spec get_order( bin_uri(), bin_key(), jws(), option_map() ) ->
		  { json_map_decoded(), bin_uri(), nonce() }.
get_order( Uri, Key, Jws, OptionMap ) ->

	trace_utils:debug_fmt( "[~w] Getting order at ~s.", [ self(), Uri ] ),

	% POST-as-GET implies no payload:

	Req = letsencrypt_jws:encode( Key, Jws#jws{ url=Uri }, _Content=undefined ),

	{ ok, #{ json := Resp, location := Location, nonce := Nonce } } =
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

	trace_utils:debug_fmt( "[~w] Requesting authorization at ~s.",
						   [ self(), Uri ] ),

	% POST-as-GET implies no payload:
	B64AuthReq = letsencrypt_jws:encode( PrivKey, Jws#jws{ url=AuthUri },
										 _Content=undefined ),

	{ ok, #{ json := Resp, location := LocationUri, nonce := Nonce } } =
		request( _Method=post, AuthUri, _Headers=#{},
				 _MaybeBinContent=B64AuthReq, OptionMap#{ json=> true } ),

	{ Resp, LocationUri, Nonce }.



% Notifies the ACME server that we are ready for challenge validation (see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
%
% Returns {Response, Location, Nonce}, where:
%		- Response is json (decoded as map)
%		- Location is create account url
%		- Nonce is a new valid replay-nonce
%
-spec notify_ready_for_challenge( directory_map(), bin_key(), jws(),
			  option_map() ) -> { json_map_decoded(), bin_uri(), nonce() }.
notify_ready_for_challenge( _DirMap=#{ <<"url">> := Uri }, Key, Jws,
							OptionMap ) ->

	trace_utils:debug_fmt( "[~w] Notifying ACME server that ready for "
						   "challenge validation at ~s.", [ self(), Uri ] ),

	% POST-as-GET implies no payload:
	Req = letsencrypt_jws:encode( Key, Jws#jws{ url=Uri }, _Content=#{} ),

	{ ok, #{ json := Resp, location := Location, nonce := Nonce } } =
		request( _Method=post, Uri, _Headers=#{}, _MaybeBinContent=Req,
				OptionMap #{ json => true } ),

	{ Resp, Location, Nonce }.



% Finalizes order once a challenge has been validated, see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.
%
-spec finalize_order( directory_map(), bin_csr_key(), bin_key(), jws(),
			  option_map() ) -> { json_map_decoded(), bin_uri(), nonce() }.
finalize_order( _DirMap=#{ <<"finalize">> := Uri }, Csr, Key, Jws,
				OptionMap ) ->

	trace_utils:debug_fmt( "[~w] Finalizing order at ~s.", [ self(), Uri ] ),

	Payload = #{ csr => Csr },

	Req = letsencrypt_jws:encode( Key, Jws#jws{ url=Uri }, Payload ),

	{ ok, #{ json := Resp, location := Location, nonce := Nonce } } =
		request( _Method=post, Uri, _Headers=#{}, _MaybeBinContent=Req,
				 OptionMap=#{ json => true } ),

	{ Resp, Location, Nonce }.



% Downloads certificate for finalized order (see
% https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2) and returns it.
%
-spec get_certificate( order_map(), tls_private_key(), jws(), option_map() ) ->
		  bin_certificate().
get_certificate( #{ <<"certificate">> := Uri }, Key, Jws, OptionMap ) ->

	trace_utils:debug_fmt( "[~w] Downloading certificate at ~s.",
						   [ self(), Uri ] ),

	% POST-as-GET implies no payload:
	Req = letsencrypt_jws:encode( Key, Jws#jws{ url=Uri }, _Content=undefined ),

	{ ok, #{ body := BinCert } } = request( _Method=post, Uri, _Headers=#{},
											_MaybeBinContent=Req, OptionMap ),

	BinCert.
