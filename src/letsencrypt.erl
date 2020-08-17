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


% Main module for Erlang Let's Encrypt.
-module(letsencrypt).

-author("Guillaume Bour <guillaume@bour.cc>").

-behaviour(gen_fsm).


% Public API:
-export([ make_cert/3, make_cert_bg/3, get_challenge/1 ]).


% FSM API:
-export([ start/1, stop/1, init/1, handle_event/3, handle_sync_event/4,
		  handle_info/3, terminate/3, code_change/4 ]).


% FSM state-related callbacks:
-export([ idle/3, pending/3, valid/3, finalize/3 ]).

% Not involving Myriad's parse transform here:
%-type maybe( T ) :: T | 'undefined'.
%-type void() :: any().
%-type table( K, V ) :: map_hashtable:map_hashtable( K, V ).


-type bin_domain() :: net_utils:bin_fqdn().

-type domain() :: net_utils:string_fqdn() | bin_domain().


% URI format compatible with the shotgun library:
-type le_mode() :: 'webroot' | 'slave' | 'standalone'.


% Note: only the 'http-01' challenge is supported currently.
-type challenge_type() :: 'http-01'.
					  % | 'tls-sni-01'.


-type challenge() :: term().

% Supposedly:
-type token() :: ustring().

-type thumbprint() :: term().

-type thumbprint_map() :: table( token(), thumbprint() ).


% All known information regarding a challenge.
%
% Keys: <<"token">>, 'thumbprint'.
%
-type challenge_map() :: map().


-type string_uri() :: ustring().

-type bin_uri() :: binary().

-type uri() :: string_uri() | bin_uri().


-type uri_challenge_type_map() :: table( bin_uri(), challenge_type() ).


-type type_challenge_map() :: table( challenge_type(), challenge_map() ).

-type option_map() :: map().

-type operation() :: any().

% ACME directory, mapping URIs to operations.
-type directory_map() :: table( operation(), uri() ).

-type nonce() :: binary().


% Subject Alternative Name, i.e. values to be associated with a security
% certificate using a subjectAltName field; see
% https://en.wikipedia.org/wiki/Subject_Alternative_Name.
%
-type san() :: ustring().

-type order_map() :: map().


% JSON element decoded as a map:
-type json_map_decoded() :: map().


% JSON Web Signature:
-type jws() :: #{ 'alg' => 'RS256',
				  'jwk' => map(),
				  nonce => maybe( nonce() ) }.


-type ssl_private_key() :: #{
		'raw' => crypto:rsa_private(),
		'b64' => { binary(), binary() },
		'file' => string() }.

-type key_file_info() :: { 'new', file_name() } | file_path().


% A certificate, as a binary:
-type bin_certificate() :: binary().

% A key, as a binary:
-type bin_key() :: binary().

% A CSR key, as a binary:
-type bin_csr_key() :: bin_key().


-export_type([ bin_domain/0, domain/0, le_mode/0,
			   challenge_type/0, challenge/0, token/0,
			   thumbprint/0, thumbprint_map/0, challenge_map/0,
			   string_uri/0, bin_uri/0, uri/0,
			   uri_challenge_type_map/0,
			   type_challenge_map/0, option_map/0, operation/0, nonce/0,
			   san/0, order_map/0, json_map_decoded/0, jws/0,
			   ssl_private_key/0, key_file_info/0,
			   bin_certificate/0, bin_key/0, bin_csr_key/0 ]).



-define( webroot_challenge_path, <<"/.well-known/acme-challenge">> ).


% State of a Let's Encrypt instance:
-record( le_state, {

	% ACME environment:
	env = prod :: staging | prod,

	% ACME directory:
	directory_map = undefined :: maybe( directory_map() ),

	%acme_srv = ?DEFAULT_API_URL :: uri() | string(),

	key_file_info = undefined :: maybe( key_file_info() ),

	% Directory where certificates are to be stored:
	cert_dir_path = <<"/tmp">> :: bin_directory_path(),

	% Ex: mode = webroot.
	mode = undefined :: maybe( le_mode() ),

	% If mode is 'webroot':
	webroot_path = undefined :: maybe( bin_directory_path() ),

	% If mode is 'standalone':
	port = 80 :: net_utils:tcp_port(),

	intermediate_cert = undefined :: maybe( bin_certificate() ),


	% State-related data:

	nonce = undefined :: maybe( nonce() ),

	domain = undefined :: maybe( net_utils:bin_fqdn() ),

	sans = [] :: [ san() ],

	% SSL private key information:
	key = undefined :: maybe( ssl_private_key() ),

	% JSON Web Signature:
	jws = undefined :: maybe( jws() ),

	account_key = undefined,

	order = undefined :: maybe( order_map() ),

	% Known challenges, per type:
	challenges = #{} :: type_challenge_map(),

	% Path to certificate/csr key file:
	cert_key_file_path = undefined :: maybe( file_path() ),

	% API options:
	opts = #{ netopts => #{ timeout => 30000 } } :: option_map()

}).

-type le_state() :: #le_state{}.

-type fsm_pid() :: pid().

% FSM status:
-type status() :: 'pending' | 'processing' | 'valid' | 'invalid' | 'revoked'.



% Shorthands:

-type count() :: basic_utils:count().
-type ustring() :: text_utils:ustring().

-type file_name() :: file_utils:file_name().
-type file_path() :: file_utils:file_path().

%-type directory_path() :: file_utils:directory_path().
-type bin_directory_path() :: file_utils:bin_directory_path().



% Starts letsencrypt service.
-spec start( list() ) -> { 'ok', fsm_pid() }
			  | {'error', { 'already_started', fsm_pid() } }.
start( Args ) ->
	gen_fsm:start_link( ?MODULE, Args, _Opts=[] ).


% Stops letsencrypt service.
-spec stop( fsm_pid() ) -> 'ok'.
stop( FsmPid ) ->
	%NOTE: maintain compatibility with 17.X versions
	%gen_fsm:stop()
	gen_fsm:sync_send_all_state_event( FsmPid, stop ).


% Initializes the state machine:
%   - init ssl & jws
%   - fetch ACME directory
%   - get valid nonce
%
% Transitions to the 'idle' state.
%
-spec init( [ atom() | { atom(), any() } ] ) -> { 'ok', 'idle', le_state() }.
init( Args ) ->

	LEState = setup_mode( getopts( Args, #le_state{} ) ),

	trace_utils:debug_fmt( "[~w] Initial state: ~p", [ self(), LEState ] ),

	% Creates key & initialises JWS:
	Key = letsencrypt_ssl:create_private_key( LEState#le_state.key_file_info,
											  LEState#le_state.cert_dir_path ),

	Jws = letsencrypt_jws:init( Key ),

	DirectoryMap = letsencrypt_api:get_directory_map( LEState#le_state.env,
													  LEState#le_state.opts ),

	% Gets first nonce:
	Nonce = letsencrypt_api:get_nonce( DirectoryMap, LEState#le_state.opts ),

	{ ok, _LEStateName=idle,
	  LEState#le_state{ directory_map=DirectoryMap,
						key=Key,
						jws=Jws,
						nonce=Nonce } }.


%%
%% PUBLIC funs
%%


% Generates a new certificate for specified domain (FQDN).
%
% params:
%	- Domain: domain name to generate an ACME certificate for
%	- Opts  : dictionary of options
%			* async (bool): if true, make_cert() blocks until complete and returns
%				generated certificate filename
%						  if false, immediately returns
%			* callback: function executed when async = true once domain certificate
%						has been successfully generated
% returns:
%	- 'async' if async is set (default)
%	- {error, Err} if something goes bad
%
-spec make_cert( fsm_pid(), Domain :: domain(), option_map() ) ->
		  {'ok', #{ cert => bin_certificate(), key => bin_key() } }
			  | {'error','invalid'}
			  | 'async'.
make_cert( FsmPid, Domain, Opts=#{ async := false } ) ->

	trace_utils:debug_fmt( "Generating async certificate for domain '~s'.",
						   [ Domain ] ),

	make_cert_bg( FsmPid, Domain, Opts );

% Default to async = true:
make_cert( FsmPid, Domain, Opts ) ->

	trace_utils:debug_fmt( "Generating sync certificate for domain '~s'.",
						   [ Domain ] ),

	_Pid = erlang:spawn( ?MODULE, make_cert_bg,
						[ FsmPid, Domain, Opts#{ async => true } ] ),
	async.


% (spawn helper)
-spec make_cert_bg( fsm_pid(), Domain :: domain(), option_map() ) ->
		  { 'ok', map() } | { 'error', 'invalid' }.
make_cert_bg( FsmPid, Domain, Opts=#{async := Async} ) ->

	BinDomain = text_utils:ensure_binary( Domain ),

	Timeout = 15000,

	Ret = case gen_fsm:sync_send_event( FsmPid,
							{ create, BinDomain, Opts }, Timeout ) of

		{ error, Error } ->
			trace_utils:error_fmt( "Creation error: ~p.", [ Error ] ),
			{ creation_error, Error };

		ok ->
			case wait_valid( FsmPid, _Count=20 ) of

				ok ->
					Status = gen_fsm:sync_send_event( FsmPid, finalize,
													  Timeout ),

					case wait_finalized( FsmPid, Status, _Count=20 ) of

						P={ ok, _SomeRes } ->
							%trace_utils:debug_fmt( "OK for '~s': ~p",
							%                     [ Domain, SomeRes ] ),
							P;

						Error ->
							%trace_utils:debug_fmt( "Error for '~s': ~p",
							%                     [ Domain, Error ] ),
							Error

					end;

				OtherError ->
					gen_fsm:send_all_state_event( FsmPid, reset ),
					trace_utils:debug_fmt( "Reset for '~s': ~p",
										   [ Domain, OtherError ] ),
					OtherError

			end;

		Other ->
			trace_utils:error_fmt("Unexpected after create: ~p", [ Other ] ),
			throw( { unexpected_create, Other } )

	end,

	case Async of

		true ->
			Callback = maps:get( callback, Opts, _Default=fun(_) -> ok end),
			Callback( Ret );

		_ ->
			ok

	end,

	%trace_utils:debug_fmt( "Return for '~s': ~p", [ Domain, Ret ] ),
	Ret.



% Returns the ongoing challenges with pre-computed thumbprints:
%   #{Challenge => Thumbrint} if ok,
%	'error' if fails
%
-spec get_challenge( fsm_pid() ) -> 'error' | challenge_map().
get_challenge( FsmPid ) ->

	case catch gen_fsm:sync_send_event( FsmPid, get_challenge ) of

		% Process not started, wrong state, etc.:
		{'EXIT', Exc } ->
			trace_utils:error_fmt( "Challenge not obtained: ~p.", [ Exc ] ),
			error;

		ChallengeMap ->
			ChallengeMap

	end.



%%
%% gen_server API
%%


% State 'idle', used when awaiting for certificate request.
%
% idle(get_challenge) :: nothing done
%
idle( get_challenge, _, LEState ) ->
	{ reply, no_challenge, idle, LEState };

% idle( {create, Domain, Opts} ).
%
% Starts a new certificate delivery process:
%  - create new account
%  - create new order
%  - require authorization (returns challenges list)
%  - initiate choosen challenge
%
% Transition to:
%  - 'idle' if process failed
%  - 'pending' waiting for challenges to be complete
%
idle( { create, Domain, _CertOpts }, _,
	  LEState=#le_state{ directory_map=DirMap, key=Key, jws=Jws, nonce=Nonce,
						 opts=Opts } ) ->

	% 'http-01' or 'tls-sni-01'
	% TODO: validate type
	ChallengeType = maps:get( challenge, Opts, _Default='http-01' ),

	%Conn  = get_conn(LEState),
	%Nonce = get_nonce(Conn, LEState),
	%TODO: SANs
	%SANs  = maps:get(san, Opts, []),

	{ Accnt, LocationURI, NewNonce } = letsencrypt_api:get_account( DirMap, Key,
											 Jws#{ nonce => Nonce }, Opts ),

	AccntKey = maps:get( <<"key">>, Accnt ),

	NewJws = #{ alg => maps:get( alg, Jws ),
				nonce => NewNonce,
				kid   => LocationURI },

	BinDomain = text_utils:ensure_binary( Domain ),

	%TODO: checks order is ok
	{ ok, Order, OrderLocation, Nonce3 } =
		letsencrypt_api:order( DirMap, BinDomain, Key, NewJws, Opts ),

	% We need to keep trace of order location:
	Order2 = Order#{ <<"location">> => OrderLocation },

	% Nonce2 = letsencrypt_api:new_reg( Conn, BasePath, Key,
	%                                   JWS#{nonce => Nonce} ),

	% AuthzResp = authz([Domain|SANs], ChallengeType,
	%     LEState#le_state{conn=Conn, nonce=Nonce2}),

	AuthUris = maps:get( <<"authorizations">>, Order ),

	AuthzResp = authz( ChallengeType, AuthUris,
		LEState#le_state{ domain=Domain, jws=NewJws, account_key=AccntKey,
						  nonce=Nonce3 } ),

	{ StateName, Reply, Challenges, Nonce5 } = case AuthzResp of

		{ error, Err, Nonce3 } ->
			{ idle, { error, Err }, nil, Nonce3 };


		{ ok, Xchallenges, Nonce4 } ->
			{ pending, ok, Xchallenges, Nonce4 }

	end,

	{reply, Reply, StateName, LEState#le_state{ domain=BinDomain, jws=NewJws,
		nonce=Nonce5, order=Order2, challenges=Challenges, sans=[],
		account_key=AccntKey } }.




% Management of the 'pending' state, when challenges are on-the-go.
%
% Returns a list of the challenges currently on-the-go with pre-computed
% thumbprints, i.e. a thumbprint_map().
%
pending( get_challenge, _Domain, LEState=#le_state{ account_key=AccntKey,
													challenges=Challenges } ) ->
	ThumbprintMap = maps:from_list(
		[ { Token, _Thumbprint=letsencrypt_jws:keyauth( AccntKey, Token ) }
		  || #{ <<"token">> := Token } <- maps:values( Challenges ) ] ),

	{ reply, ThumbprintMap, pending, LEState };


% Checks if all challenges are completed.
% Switch to 'valid' state iff all challenges are validated only.
%
% Transitions to:
%	- 'pending' if at least one challenge is not complete yet
%	- 'valid' if all challenges are complete
%
% TODO: handle other states explicitely (allowed values are 'invalid',
% 'deactivated', 'expired' and 'revoked')
%
pending( _CheckAction, _Domain,
		 LEState=#le_state{ order=#{<<"authorizations">> := Authzs},
							nonce=Nonce, key=Key, jws=Jws, opts=Opts } ) ->

	% Checking status for each authorization:
	{ LEStateName, Nonce2 } = lists:foldl(
		fun( AuthzUri, _Acc={ Status, InNonce } ) ->
			{ok, Authz, _, OutNonce } = letsencrypt_api:authorization( AuthzUri,
								Key, Jws#{ nonce => InNonce }, Opts ),

			Status2 = maps:get( <<"status">>, Authz ),

			%{ Status2, Msg2 } = letsencrypt_api:challenge( Challengestatus,
			%Conn, UriPath ), io:format( "~p: ~p (~p)~n", [ _K, Status2, Msg2 ]
			%),

			Ret = case { Status, Status2 } of

				{ valid, <<"valid">> } ->
					valid;

				{ pending, _ } ->
					pending;

				{ _, <<"pending">> } ->
					pending;

				%TODO: we must not let that openbar :)
				{ valid, Status2 } ->
					Status2 ;

				{ Status , _ } ->
					Status

			end,

			{ Ret, OutNonce }

		end,
		_Acc0={ valid, Nonce },
		_List=Authzs ),

	%io:format(":: challenge state -> ~p~n", [Reply]),
	% reply w/ LEStateName

	{ reply, LEStateName, LEStateName, LEState#le_state{ nonce=Nonce2 } }.



% Management of the 'valid' state.
%
% When challenges have been successfully completed, finalizes ACME order and
% generates TLS certificate.
%
% returns:
%	Status: order status
%
% Transitions to 'finalize' state.
%
valid( _Action, _Domain,
	   LEState=#le_state{ mode=Mode, domain=BinDomain, sans=SANs,
						  cert_dir_path=CertDirPath, order=Order, key=Key, jws=Jws,
						  nonce=Nonce, opts=Opts } ) ->

	challenge_destroy( Mode, LEState ),

	KeyFilename = text_utils:binary_to_string( BinDomain ) ++ ".key",

	% KeyFilePath is required for csr generation:
	#{ file := KeyFilePath } =
		letsencrypt_ssl:create_private_key( { new, KeyFilename }, CertDirPath ),

	Csr = letsencrypt_ssl:get_cert_request( BinDomain, CertDirPath, SANs ),

	{ ok, FinOrder, _, FinNonce } = letsencrypt_api:finalize( Order, Csr, Key,
											 Jws#{ nonce => Nonce }, Opts ),

	BinStatus = maps:get( <<"status">>, FinOrder, nil ),

	Status = letsencrypt_api:binary_to_status( BinStatus ),

	LocOrder = FinOrder#{ <<"location">> => maps:get( <<"location">>, Order ) },

	{ reply, Status, finalize, LEState#le_state{ order=LocOrder,
								 cert_key_file_path=KeyFilePath, nonce=FinNonce } }.



% Management of the 'finalize' state.
%
% When order is being finalized, and certificate generation is ongoing.
%
% Wait for certificate generation being complete (order status == 'valid').
%
% Returns the order status.
%
% Transitions to:
%   state 'processing' : still ongoing
%   state 'valid'      : certificate is ready
%
finalize( processing, _Domain, LEState=#le_state{ order=OrderMap, key=Key, jws=Jws,
												  nonce=Nonce, opts=Opts } ) ->

	Loc = maps:get( <<"location">>, OrderMap, nil ),

	{ NewOrderMap, _Loc, NewNonce } =
		letsencrypt_api:get_order( Loc, Key, Jws#{ nonce => Nonce }, Opts ),

	BinStatus = maps:get( <<"status">>, NewOrderMap, nil ),

	Status = letsencrypt_api:binary_to_status( BinStatus ),

	{ reply, Status, finalize,
	  LEState#le_state{ order=NewOrderMap, nonce=NewNonce } };


% Downloads certificate and saves it into file.
%
% Returns #{key, cert} where;
%		- Key is certificate private key filename
%		- Cert is certificate PEM filename
%
% Transitions to state 'idle': fsm complete, going back to initial state.
%
finalize( valid, _Domain, LEState=#le_state{ order=OrderMap, domain=BinDomain,
						cert_key_file_path=KeyFilePath, cert_dir_path=CertDirPath,
						key=Key, jws=Jws, nonce=Nonce, opts=Opts } ) ->

	BinKeyFilePath = text_utils:string_to_binary( KeyFilePath ),

	% Downloads certificate:
	BinCert = letsencrypt_api:get_certificate( OrderMap, Key,
							Jws#{ nonce => Nonce }, Opts ),

	CertFilePath = letsencrypt_ssl:write_certificate( BinDomain, BinCert,
													  CertDirPath ),

	BinCertFilePath = text_utils:string_to_binary( CertFilePath ),

	{ reply, { ok, #{ key => BinKeyFilePath, cert => BinCertFilePath } }, idle,
	  LEState#le_state{ nonce=undefined } };


% Any other order status leads to exception.
finalize( UnexpectedStatus, _Domain, LEState ) ->

	trace_utils:error_fmt( "Unknown finalize status: ~p.",
						  [ UnexpectedStatus ] ),

	{ reply, { error, UnexpectedStatus }, finalize, LEState }.



% Callback section.

handle_event( reset, _StateName, LEState=#le_state{ mode=Mode } ) ->
	%trace_utils:debug_fmt( "Reset from ~p state.", [ StateName ] ),
	challenge_destroy( Mode, LEState ),
	{ next_state, idle, LEState };

handle_event( _, StateName, LEState ) ->
	trace_utils:debug_fmt( "Async event: ~p.", [ StateName ] ),
	{ next_state, StateName, LEState }.



handle_sync_event( stop, _, _, _ ) ->
	{ stop, normal, ok, #le_state{} };

handle_sync_event( _, _, StateName, LEState ) ->
	trace_utils:debug_fmt( "Sync event: ~p.", [ StateName ] ),
	{ reply, ok, StateName, LEState }.


handle_info( _, StateName, LEState ) ->
	{ next_state, StateName, LEState }.


terminate( _, _, _ ) ->
	ok.


code_change( _, StateName, LEState, _ ) ->
	{ ok, StateName, LEState }.



%%
%% PRIVATE functions
%%


% Parses letsencrypt:start() options.
%
% Available options are:
%   - staging: runs in staging environment (running on production either)
%   - key_file_path: reuse an existing TLS key
%   - cert_dir_path: path to read/save ssl certificate, key and csr request
%   - http_timeout: timeout for acme api requests (seconds)
%
% Returns LEState (type record 'le_state') filled with options values
%
-spec getopts( [ atom() | { atom(), any() } ], le_state() ) -> le_state().
getopts( _Opts=[], LEState ) ->
	LEState;

getopts( _Opts=[ staging | T ], LEState ) ->
	getopts( T, LEState#le_state{ env=staging } );

getopts( _Opts=[ { mode, Mode } | T ], LEState ) ->
	getopts( T, LEState#le_state{ mode=Mode } );

getopts( _Opts=[ { key_file_path, KeyFilePath } | T ], LEState ) ->
	getopts( T, LEState#le_state{ key_file_info=KeyFilePath } );

getopts( _Opts=[ { cert_dir_path, CertDirPath } | T ], LEState ) ->
	getopts( T, LEState#le_state{
				  cert_dir_path=text_utils:string_to_binary( CertDirPath ) } );

getopts( _Opts=[ { webroot_dir_path, WebDirPath } | T ], LEState ) ->
	getopts( T, LEState#le_state{
				  webroot_path=text_utils:string_to_binary( WebDirPath ) } );

getopts( _Opts=[ { port, Port } | T ], LEState ) ->
	getopts( T, LEState#le_state{ port=Port } );

getopts( _Opts=[ { http_timeout, Timeout } | T ], LEState ) ->
	getopts( T, LEState#le_state{ opts=#{
							netopts => #{ timeout => Timeout } } } );

getopts( _Opts=[ Unexpected | _T ], _LEState ) ->
	trace_utils:error_fmt( "Invalid option: ~p.", [ Unexpected ] ),
	throw( { invalid_option, Unexpected } ).



% Setups the context of chosen mode.
-spec setup_mode( le_state() ) -> le_state().
setup_mode( #le_state{ mode=webroot, webroot_path=undefined } ) ->
	trace_utils:error( "Missing 'webroot_path' parameter." ),
	throw( webroot_path_missing );

setup_mode( LEState=#le_state{ mode=webroot, webroot_path=BinWebrootPath } ) ->

	% TODO: check directory is writable
	ChallengeDirPath =
		file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

	file_utils:create_directory_if_not_existing( ChallengeDirPath,
												 create_parents ),

	LEState;

setup_mode( LEState=#le_state{ mode=standalone, port=_Port } ) ->
	% TODO: checking port is unused?
	LEState;

setup_mode( LEState=#le_state{ mode=slave } ) ->
	LEState;

% Every other mode value is invalid:
setup_mode( #le_state{ mode=Mode } ) ->
	trace_utils:error_fmt( "Invalid '~p' mode.", [ Mode ] ),
	throw( { invalid_mode, Mode } ).



% Loops X times on authorization check until challenges are all validated (waits
% incrementing time between each trial).
%
% Returns:
%   - {error, timeout} if failed after X loops
%   - {error, Err} if another error
%   - 'ok' if succeed
%
-spec wait_valid( fsm_pid(), count() ) -> 'ok' | { 'error', any() }.
wait_valid( FsmPid, C ) ->
	wait_valid( FsmPid, C, C ).


% (helper)
-spec wait_valid( fsm_pid(), count(), count() ) -> 'ok' | { 'error', any() }.
wait_valid( _FsmPid, 0, _C ) ->
	{ error, timeout };

wait_valid( FsmPid, Count, Max ) ->
	case gen_fsm:sync_send_event( FsmPid, check, _Timeout=15000 ) of

		valid ->
			ok;

		pending ->
			timer:sleep( 500 * ( Max - Count + 1 ) ),
			wait_valid( FsmPid, Count - 1, Max );

		{ _Other, Error } ->
			{ error, Error }

	end.


% wait_finalized(X).
%
% Loops X times on order being finalized (waits incrementing time between each
% trial).
%
% Returns:
%   - {error, timeout} if failed after X loops
%   - {error, Err} if another error
%   - {'ok', Response} if succeed
%
-spec wait_finalized( fsm_pid(), status(), count() ) ->
		  { 'ok', map() } | { 'error', 'timeout' | any() }.
wait_finalized( FsmPid, Status, C ) ->
	wait_finalized( FsmPid, Status, C, C ).


% (helper)
-spec wait_finalized( status(), count(), count() ) ->
		  { 'ok', map() } | { 'error', 'timeout' | any() }.
wait_finalized( _FsmPid, _Status, _Count=0, _Max ) ->
	{ error, timeout };

wait_finalized( FsmPid, Status, Count, Max ) ->

	case gen_fsm:sync_send_event( FsmPid, Status, _Timeout=15000 ) of

		P={ ok, _Res } ->
			P;

		valid ->
			timer:sleep( 500 * ( Max - Count + 1 ) ),
			wait_finalized( FsmPid, valid, Count-1, Max );

		processing  ->
			timer:sleep( 500 * ( Max - Count + 1 ) ),
			wait_finalized( FsmPid, processing, Count-1, Max );

		{ _, Error } ->
			{ error, Error };

		Any ->
			Any

	end.



% Performs ACME authorization and selected challenge initialization.
-spec authz( challenge_type(), [ bin_uri() ], le_state() ) ->
		  { 'ok', uri_challenge_type_map(), nonce() }
		| { 'error', 'uncaught' | binary(), nonce() }.
authz( ChallengeType, AuthzUris, LEState=#le_state{ mode=Mode } ) ->

	case authz_step1( AuthzUris, ChallengeType, LEState, _Challenges=#{} ) of

		T={ error, _Error, _Nonce } ->
			T;

		{ ok, Challenges, Nonce } ->
			%trace_utils:debug_fmt( "Challenges: ~p.", [ Challenges ] ),
			challenge_init( Mode, LEState, ChallengeType, Challenges ),

			case authz_step2( maps:to_list( Challenges ),
							  LEState#le_state{ nonce=Nonce } ) of

				{ ok, NewNonce } ->
					{ ok, Challenges, NewNonce };

				Error ->
					Error

			end
	end.



% Requests authorizations.
%
% returns:
%   {ok, Challenges, Nonce}
%		- Challenges is map of Uri -> Challenge, where Challenge is of ChallengeType type
%		- Nonce is a new valid replay-nonce
%
-spec authz_step1( [ bin_uri() ], challenge_type(), le_state(),
				   uri_challenge_type_map() ) ->
		  { 'ok', uri_challenge_type_map(), nonce() }
		| { 'error', 'uncaught' | binary(), nonce() }.
authz_step1( _URIs=[], _ChallengeType, #le_state{ nonce=Nonce }, URIChallengeMap ) ->
	{ ok, URIChallengeMap, Nonce };

authz_step1( _URIs=[ Uri | T ], ChallengeType,
			 LEState=#le_state{ nonce=Nonce, key=Key, jws=Jws, opts=Opts },
			 URIChallengeMap ) ->

	AuthzRet =
		letsencrypt_api:authorization( Uri, Key, Jws#{ nonce => Nonce }, Opts ),

	trace_utils:debug_fmt( "Authzret for URI '~s': ~p.", [ AuthzRet, Uri ] ),

	case AuthzRet of

		%T={ error, _Error, _Nonce } ->
		%    T;

		{ ok, Authz, _, NewNonce } ->

			BinChallengeType = atom_to_binary( ChallengeType ),

			[ Challenge ] = lists:filter(
				fun( CMap ) ->
					maps:get( <<"type">>, CMap, _Default=error )
						=:= BinChallengeType
				end,
				maps:get( <<"challenges">>, Authz )
			),

			authz_step1( T, ChallengeType, LEState#le_state{ nonce=NewNonce },
						 URIChallengeMap#{ Uri => Challenge } )
	end.



% Second step of the authorization process, executed after challenge
% initialization.
%
% Notifies the ACME server the challenges are good to proceed.
%
-spec authz_step2( [ { bin_uri(), challenge() } ], le_state()) ->
		  { 'ok', nonce() } | {'error', binary(), nonce() }.
authz_step2( _Pairs=[], #le_state{ nonce=Nonce } ) ->
	{ ok, Nonce };

authz_step2( _Pairs=[ {_Uri, Challenge } | T ],
			 LEState=#le_state{ nonce=Nonce, key=Key, jws=Jws, opts=Opts } ) ->
	{ ok, _, _, OtherNonce } = letsencrypt_api:challenge( Challenge, Key,
											  Jws#{ nonce => Nonce }, Opts ),

	authz_step2( T, LEState#le_state{ nonce=OtherNonce } ).



% Initializes the local configuration to serve specified challenge type.
%
% Depends on challenge type & mode.
%
% TODO: ChallengeType is included in Challenges (<<"type">> key). To refactor
%
-spec challenge_init( le_mode(), le_state(), challenge_type(), map() ) -> void().
challenge_init( _Mode=webroot, #le_state{ webroot_path=BinWPath,
										  account_key=AccntKey },
				_ChallengeType='http-01', Challenges ) ->

	[ begin

		ChalWebPath = file_utils:join(
						  [ BinWPath, ?webroot_challenge_path, Token ] ),

		Thumbprint = letsencrypt_jws:keyauth( AccntKey, Token ),

		% Hopefully the default modes are fine:
		file_utils:write_whole( ChalWebPath, Thumbprint, _Modes=[] )

	  end || #{ <<"token">> := Token } <- maps:values( Challenges ) ];

challenge_init( _Mode=slave, _LEState, _ChallengeType, _Challenges ) ->
	ok;

challenge_init( _Mode=standalone, #le_state{ port=Port, domain=Domain,
									   account_key=AccntKey },
				ChallengeType, Challenges ) ->

	%trace_utils:debug_fmt( "Init standalone challenge for ~p.",
	%                       [ ChallengeType ] ),

	{ok, _ } = case ChallengeType of

		'http-01' ->
			% elli webserver callback args is:
			% #{Domain => #{
			%     Token => Thumbprint,
			%     ...
			% }}
			%

			% Iterating on values:
			Thumbprints = maps:from_list(
				[ { Token, letsencrypt_jws:keyauth( AccntKey, Token ) }
				  || #{ <<"token">> := Token } <- maps:values( Challenges ) ] ),

			elli:start_link([
				{ name, { local, letsencrypt_elli_listener } },
				{ callback, letsencrypt_elli_handler },
				{ callback_args, [ #{ Domain => Thumbprints } ] },
				{ port, Port } ] );

		%'tls-sni-01' ->
		%   TODO

		_ ->
			trace_utils:error_fmt( "Standalone mode: unsupported ~p challenge "
								   "type.", [ ChallengeType ] ),

			throw( { unsupported_challenge_type, ChallengeType, standalone } )

	end.


% Cleans up challenge context after it has been fullfilled (with success or not); in:
%
% - 'webroot' mode: delete token file
% - 'standalone' mode: stop internal webserver
% - 'slave' mode: nothing to do
%
-spec challenge_destroy( le_mode(), le_state() ) -> void().
challenge_destroy( _Mode=webroot,
				   #le_state{ webroot_path=BinWPath, challenges=Challenges } ) ->

	[ begin

		  ChalWebPath = file_utils:join(
						  [ BinWPath, ?webroot_challenge_path, Token ] ),

		  file_utils:remove_file( ChalWebPath )

	  end || #{ <<"token">> := Token } <- maps:values( Challenges ) ];


challenge_destroy( _Mode=standalone, _LEState ) ->

	% Stop http server:
	elli:stop( letsencrypt_elli_listener );


challenge_destroy( _Modeslave, _LEState ) ->
	ok.
