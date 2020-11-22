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


% Main module for LEEC, the Ceylan Let's Encrypt Erlang fork.
%
% Original 'Let's Encrypt Erlang' application:
% https://github.com/gbour/letsencrypt-erlang
%
-module(letsencrypt).

% Original work:
-author("Guillaume Bour (guillaume at bour dot cc)").

% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com").


% Replaces the deprecated gen_fsm; we use here the 'state_functions' callback
% mode, so:
%  - events are handled by one callback function *per state*
%  - state names must be atom-only
%
-behaviour(gen_statem).


% This is a (passive) application:
-behaviour(application).


% Public API:
-export([ get_ordered_prerequisites/0,
		  start/1, get_default_options/0, get_default_options/1,
		  obtain_certificate_for/2, obtain_certificate_for/3, stop/1 ]).


% For testing purpose:
-export([ get_ongoing_challenges/1 ]).


% For spawn purpose:
-export([ obtain_cert_helper/3 ]).


% FSM gen_statem base API:
-export([ init/1, callback_mode/0, terminate/3, code_change/4 ]).


% FSM state-corresponding callbacks:
-export([ idle/3, pending/3, valid/3, finalize/3 ]).


% Implementation notes:
%
% Multiple FSM (Finite State Machines) can be spawned, for parallel certificate
% management.
%
% URI format compatible with the shotgun library.


% Not involving Myriad's parse transform here:
-type maybe( T ) :: T | 'undefined'.
-type void() :: any().
-type table( K, V ) :: map_hashtable:map_hashtable( K, V ).

% To silence if not compiled with rebar3:
-export_type([ maybe/1, void/0, table/2 ]).


-type bin_domain() :: net_utils:bin_fqdn().

-type domain() :: net_utils:string_fqdn() | bin_domain().


% Three ways of interfacing LEEC with user code:
-type le_mode() :: 'webroot' | 'slave' | 'standalone'.


% The PID of a LEEC FSM:
-type fsm_pid() :: pid().


% Note: only the 'http-01' challenge is supported currently.
-type challenge_type() :: 'http-01'
						| 'tls-sni-01'
						| 'dns-01'.


% Challenge type, as a binary string:
-type bin_challenge_type() :: text_utils:bin_string().


% Supposedly:
-type token() :: ustring().

% A JSON-encoded key:
-type thumbprint() :: json().

-type thumbprint_map() :: table( token(), thumbprint() ).



-type string_uri() :: ustring().

-type bin_uri() :: binary().

-type uri() :: string_uri() | bin_uri().


% All known information regarding a challenge.
%
% As Key => example of associated value:
% - <<"status">> => <<"pending">>
% - <<"token">> => <<"qVTx6gQWZO4Dt4gUmnaTQdwTRkpaSnMiRx8L7Grzhl8">>
% - <<"type">> => <<"http-01">>,
% - <<"url">> =>
%     <<"https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/132509381/-Axkdw">>}}.
%
-type challenge() :: table:table().


-type uri_challenge_map() :: table( bin_uri(), challenge() ).


-type type_challenge_map() :: table( challenge_type(), challenge() ).


% A user-specified option:
-type user_option() :: 'staging'
					 | { 'mode', le_mode() }
					 | { 'key_file_path', any_file_path() }
					 | { 'cert_dir_path', any_directory_path() }
					 | { 'webroot_dir_path', any_directory_path() }
					 | { 'port', tcp_port() }
					 | { 'http_timeout', unit_utils:milliseconds() }.


% User options.
-type option_id() :: 'async' | 'callback' | 'netopts' | 'challenge'.


% Storing user options.
%
% Known (atom) keys:
%  - async :: boolean() [if not defined, supposed true]
%  - callback :: fun/1
%  - netopts :: map() => #{ timeout => non_neg_integer() }
%  - challenge :: challenge_type(), default being 'http-01'
%
-type option_map() :: table( option_id(), term() ).


% ACME operations that may be triggered.
%
% Known operations:
% - <<"newAccount">>
% - <<"newNonce">>
% - <<"newOrder">>
% - <<"revokeCert">>
%
-type acme_operation() :: bin_string().


% ACME directory, converting operations to trigger into the URIs to access for
% them.
%
-type directory_map() :: table( acme_operation(), uri() ).

-type nonce() :: binary().


% Subject Alternative Name, i.e. values to be associated with a security
% certificate using a subjectAltName field.
%
% See https://en.wikipedia.org/wiki/Subject_Alternative_Name.
%
-type san() :: ustring().

-type bin_san() :: bin_string().


% JSON element decoded as a map:
-type json_map_decoded() :: map().


% Information regarding the private key of the LEEC agent:
-type agent_key_file_info() :: { 'new', file_path() } | file_path().


% A certificate, as a binary:
-type bin_certificate() :: binary().

% A key, as a binary:
-type bin_key() :: binary().

% A CSR key, as a binary:
-type bin_csr_key() :: bin_key().

-type jws_algorithm() :: 'RS256'.

% A binary that is encoded in base 64:
-type binary_b64() :: binary().


% Key authorization, a binary made of a token and of the hash of a key
% thumbprint, once b64-encoded:
%
-type key_auth() :: binary().


% For the records introduced:
-include("letsencrypt.hrl").

-type tls_private_key() :: #tls_private_key{}.


-type tls_public_key() :: #tls_public_key{}.

-type jws() :: #jws{}.

-type certificate() :: #certificate{}.

% Need by other LEEC modules:
-type le_state() :: #le_state{}.

-export_type([ bin_domain/0, domain/0, le_mode/0, fsm_pid/0,
			   challenge_type/0, bin_challenge_type/0,
			   token/0, thumbprint/0, thumbprint_map/0,
			   string_uri/0, bin_uri/0, uri/0,
			   challenge/0, uri_challenge_map/0, type_challenge_map/0,
			   user_option/0, option_id/0, option_map/0,
			   acme_operation/0, directory_map/0, nonce/0,
			   san/0, bin_san/0, json_map_decoded/0, agent_key_file_info/0,
			   bin_certificate/0, bin_key/0, bin_csr_key/0,
			   jws_algorithm/0, binary_b64/0, key_auth/0,
			   tls_private_key/0, tls_public_key/0, jws/0, certificate/0,
			   le_state/0 ]).


% Where Let's Encrypt will attempt to find answers to its http-01 challenges:
-define( webroot_challenge_path, <<".well-known/acme-challenge">> ).


% Default overall http time-out, in milliseconds:
-define( default_timeout, 30000 ).

% Base time-out, in milliseconds:
-define( base_timeout, 15000 ).







% Typically fsm_pid():
-type server_ref() :: gen_statem:server_ref().

-type state_callback_result() ::
		gen_statem:state_callback_result( gen_statem:action() ).


% FSM status (corresponding to state names):
-type status() :: 'pending' | 'processing' | 'valid' | 'invalid' | 'revoked'.

-type request() :: atom().

-type state_name() :: status().

-type event_type() :: gen_statem:event_type().

-type event_content() :: term().

%-type action() :: gen_statem:action().



% Shorthands:

-type count() :: basic_utils:count().
-type error_term() :: basic_utils:error_term().
-type base_status() :: basic_utils:base_status().

-type ustring() :: text_utils:ustring().
-type bin_string() :: text_utils:bin_string().

-type file_path() :: file_utils:file_path().
-type bin_file_path() :: file_utils:bin_file_path().
-type any_file_path() :: file_utils:any_file_path().

-type any_directory_path() :: file_utils:any_directory_path().


-type tcp_port() :: net_utils:tcp_port().

-type json() :: json_utils:json().

-type application_name() :: otp_utils:application_name().



% Public API.


% Returns an (ordered) list of the LEEC prerequisite OTP applications, to be
% started in that order.
%
% Notes:
% - not listed here (not relevant for that use case): elli, getopt, yamerl,
% erlang_color
% - jsx preferred over jiffy; yet neither needs to be initialized as an
% application
% - no need to start myriad either
%
-spec get_ordered_prerequisites() -> [ application_name() ].
get_ordered_prerequisites() ->
	[ shotgun ].


% Starts an instance of the LEEC service FSM.
-spec start( [ user_option() ] ) -> { 'ok', fsm_pid() } | error_term().
start( UserOptions ) ->

	trace_bridge:trace_fmt( "Starting, with following options:~n  ~p.",
							[ UserOptions ] ),

	JsonParserState = json_utils:start_parser(),

	{ ok, _AppNames } = application:ensure_all_started( leec ),

	% Usually none, already started by framework (ex: otp_utils):
	%trace_bridge:debug_fmt( "Applications started: ~p.", [ AppNames ] ),

	% Not registered in naming service on purpose, to allow for concurrent ACME
	% interactions (i.e. multiple, parallel instances).
	%
	% Calls init/1 on the new process, and returns its outcome:
	gen_statem:start_link( ?MODULE, { UserOptions, JsonParserState },
						   _Opts=[] ).



% Returns the default API-level user options, here enabling the async
% (non-blocking) mode.
%
-spec get_default_options() -> option_map().
get_default_options() ->
	get_default_options( _Async=true ).


% Returns the default API-level user options, with specified async mode
% specified.
%
-spec get_default_options( boolean() ) -> option_map().
get_default_options( Async ) when is_boolean( Async ) ->
	#{ async => Async, netopts => #{ timeout => ?default_timeout } }.



% Generates, once started, asynchronously (in a non-blocking manner), a new
% certificate for the specified domain (FQDN).
%
% Parameters:
% - Domain is the domain name to generate an ACME certificate for
% - FsmPid is the PID of the FSM to rely on
%
% Returns:
% - 'async' if async is set (the default being sync)
% - {error, Err} if a failure happens
%
% Belongs to the user-facing API; requires the LEEC service to be already
% started.
%
-spec obtain_certificate_for( domain(), fsm_pid() ) -> 'async' | error_term().
obtain_certificate_for( Domain, FsmPid ) ->
	obtain_certificate_for( Domain, FsmPid, get_default_options() ).



% Generates, once started, synchronously (in a blocking manner) or not, a new
% certificate for the specified domain (FQDN).
%
% Parameters:
%	- Domain is the domain name to generate an ACME certificate for
%   - FsmPid is the PID of the FSM to rely on
%	- OptionMap corresponds to the API-level user options:
%			* async (bool): if true, blocks until complete and returns
%				generated certificate filename
%							if false, immediately returns
%			* callback: function executed when async = true once domain
%				certificate has been successfully generated
%
% Returns:
%	- 'async' if async is set (the default being sync)
%	- {error, Err} if a failure happens
%
% Belongs to the user-facing API; requires the LEEC service to be already
% started.
%
-spec obtain_certificate_for( Domain :: domain(), fsm_pid(), option_map() ) ->
		'async' | { 'certificate_ready', bin_file_path() } | error_term().
obtain_certificate_for( Domain, FsmPid, OptionMap=#{ async := false } ) ->

	% Still in user process:
	trace_bridge:debug_fmt( "Requesting FSM ~w to generate sync certificate "
							"for domain '~s'.", [ FsmPid, Domain ] ),

	% Direct synchronous return:
	obtain_cert_helper( Domain, FsmPid, OptionMap );


% Default to async=true:
obtain_certificate_for( Domain, FsmPid, OptionMap ) ->

	trace_bridge:debug_fmt( "Requesting FSM ~w to generate async certificate "
							"for domain '~s'.", [ FsmPid, Domain ] ),

	% Asynchronous (either already true, or set to true if not):
	_Pid = erlang:spawn_link( ?MODULE, obtain_cert_helper,
							  [ Domain, FsmPid, OptionMap#{ async => true } ] ),

	async.



% Stops the specified instance of LEEC service.
-spec stop( fsm_pid() ) -> void().
stop( FsmPid ) ->

	trace_bridge:trace_fmt( "Requesting FSM ~w to stop.", [ FsmPid ] ),

	% No more gen_fsm:sync_send_all_state_event/2 available, so
	% handle_call_for_all_states/4 will have to be called from all states
	% defined:
	%
	% (synchronous)
	%
	Res = gen_statem:call( _ServerRef=FsmPid, _Request=stop, ?base_timeout ),

	% Not stopped here, as stopping is only going back to the 'idle' state:
	%json_utils:stop_parser().

	trace_bridge:trace_fmt( "FSM ~w stopped (result: ~p).", [ FsmPid, Res ] ).





% FSM internal API.


% Initializes the LEEC state machine:
% - init TLS private key and its JWS
% - fetch ACME directory
% - get valid nonce
%
% Transitions to the 'idle' initial state.
%
-spec init( { [ user_option() ], json_utils:parser_state() } ) ->
		{ 'ok', InitialStateName :: 'idle', InitialData :: le_state() }.
init( { UserOptions, JsonParserState } ) ->

	LEState = setup_mode( get_options( UserOptions,
				   #le_state{ json_parser_state=JsonParserState } ) ),

	%trace_bridge:debug_fmt( "[~w] Initial state:~n  ~p", [ self(), LEState ] ),

	BinCertDirPath = LEState#le_state.cert_dir_path,

	% Creates the private key (a tls_private_tls_public_key()) of this LEEC
	% agent, and initialises its JWS; in case of parallel creations, ensuring
	% automatically the uniqueness of its filename is not trivial:
	%
	KeyFileInfo = case LEState#le_state.agent_key_file_info of

		% Most probably the case:
		undefined ->
			% We prefer here devising out own agent filename, lest its automatic
			% uniqueness is difficult to obtain (which is the case); we may use
			% in the future any user-specified identifier (see user_id field);
			% for now we stick to a simple approach based on the PID of this
			% LEEC FSM (no domain known yet):
			%
			%UniqFilename = text_utils:format( "letsencrypt-agent-~s.key",
			%								   [ LEState#le_state.user_id ] ),

			% A prior run might have left a file with the same name, it will be
			% overwritten (with a warning) in this case:
			%
			UniqFilename = text_utils:format( "leec-agent-~s.key",
								  [ text_utils:pid_to_core_string( self() ) ] ),

			{ new, UniqFilename };

		KInf ->
			KInf

	end,

	AgentPrivateKey = letsencrypt_tls:create_private_key( KeyFileInfo,
														  BinCertDirPath ),

	KeyJws = letsencrypt_jws:init( AgentPrivateKey ),

	OptionMap = LEState#le_state.option_map,

	% Directory map is akin to:
	%
	% #{<<"3TblEIQUCPk">> =>
	%	  <<"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/31417">>,
	%   <<"keyChange">> =>
	%	  <<"https://acme-staging-v02.api.letsencrypt.org/acme/key-change">>,
	%   <<"meta">> =>
	%	  #{<<"caaIdentities">> => [<<"letsencrypt.org">>],
	%		<<"termsOfService">> =>
	%	<<"https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf">>,
	%		<<"website">> =>
	%			<<"https://letsencrypt.org/docs/staging-environment/">>},
	%   <<"newAccount">> =>
	%	  <<"https://acme-staging-v02.api.letsencrypt.org/acme/new-acct">>,
	%   <<"newNonce">> =>
	%	  <<"https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce">>,
	%   <<"newOrder">> =>
	%	  <<"https://acme-staging-v02.api.letsencrypt.org/acme/new-order">>,
	%   <<"revokeCert">> =>
	%	  <<"https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert">>}

	URLDirectoryMap = letsencrypt_api:get_directory_map( LEState#le_state.env,
												 OptionMap, LEState ),

	FirstNonce = letsencrypt_api:get_nonce( URLDirectoryMap, OptionMap,
											LEState ),

	trace_bridge:trace_fmt( "[~w][state] Switching initially to 'idle'.",
							[ self() ] ),

	% Next transition typically triggered by user code calling
	% obtain_certificate_for/{2,3}:
	%
	{ ok, _NewStateName=idle,
	  LEState#le_state{ directory_map=URLDirectoryMap,
						agent_private_key=AgentPrivateKey,
						jws=KeyJws,
						nonce=FirstNonce } }.



% One callback function per state, akin to gen_fsm:
-spec callback_mode() -> gen_statem:callback_mode().
callback_mode() ->
	% state_enter useful to trigger code once, when entering the 'finalize'
	% state for the first time:
	%
	[ state_functions, state_enter ].



% (spawn helper, to be called either from a dedicated process or not, depending
% on being async or not)
%
-spec obtain_cert_helper( Domain :: domain(), fsm_pid(), option_map() ) ->
		  { 'certificate_ready', bin_file_path() } | error_term().
obtain_cert_helper( Domain, FsmPid, OptionMap=#{ async := Async } ) ->

	Timeout = maps:get( timeout, OptionMap, ?default_timeout ),

	BinDomain = text_utils:ensure_binary( Domain ),

	% Expected to be in the 'idle' state, hence to trigger idle({create,
	% BinDomain, Opts}, _, LEState):
	%
	CreationRes = case gen_statem:call( _ServerRef=FsmPid,
				_Request={ create, BinDomain, OptionMap }, Timeout ) of

		% State of FSM shall thus be 'idle' now:
		ErrorTerm={ creation_failed, Error } ->
			trace_bridge:error_fmt( "Creation error reported by FSM ~w: ~p.",
									[ FsmPid, Error ] ),
			{ error, ErrorTerm };

		% State of FSM shall thus be 'pending' now; should then transition after
		% some delay to 'valid'; we wait for it:
		%
		creation_pending ->

			trace_bridge:debug_fmt( "FSM ~w reported that creation is pending, "
				"waiting for the validation of challenge(s).", [ FsmPid ] ),

			case wait_challenges_valid( FsmPid ) of

				ok ->
					% So here the FSM is expected to have switched from
					% 'pending' to 'valid'. Then:

					% Most probably 'valid':
					_LastReadStatus = gen_statem:call( _ServerRef=FsmPid,
											   _Req=switchTofinalize, Timeout ),

					case wait_creation_completed( FsmPid, _Count=20 ) of

						Reply={ certificate_ready, BinCertFilePath } ->
							trace_bridge:debug_fmt( "Domain '~s' finalized "
								"for ~w, returning certificate path '~s'.",
								[ Domain, FsmPid, BinCertFilePath ] ),
							Reply;

						Error ->
							trace_bridge:error_fmt( "Error for FSM ~w when "
								"finalizing domain '~s': ~p.",
								[ FsmPid, Domain, Error ] ),
							Error

					end;

				% Typically {error, timeout}:
				OtherError ->
					trace_bridge:debug_fmt( "Reset of FSM ~w for '~s' "
						"after error ~p.", [ FsmPid, Domain, OtherError ] ),
					_ = gen_statem:call( _ServerRef=FsmPid, reset ),
					OtherError

			end;

		Other ->
			trace_bridge:error_fmt( "Unexpected return after create for ~w: ~p",
									[ FsmPid, Other ] ),
			throw( { unexpected_create, Other, FsmPid } )

	end,

	case Async of

		true ->
			Callback = maps:get( callback, OptionMap,
				_DefaultCallback=fun( Ret ) ->
					trace_bridge:warning_fmt( "Default async callback called "
						"for ~w regarding result ~p.", [ FsmPid, Ret ] )
								 end ),

			Callback( CreationRes );

		_ ->
			ok

	end,

	%trace_bridge:debug_fmt( "Return for domain '~s' creation (FSM: ~w): ~p",
	%                       [ Domain, FsmPid, CreationRes ] ),

	CreationRes.



% Returns the ongoing challenges with pre-computed thumbprints:
%   #{Challenge => Thumbrint} if ok,
%	'error' if fails
%
% Defined separately for testing.
%
-spec get_ongoing_challenges( fsm_pid() ) ->
					'error' | 'no_challenge' | thumbprint_map().
get_ongoing_challenges( FsmPid ) ->

	case catch gen_statem:call( _ServerRef=FsmPid,
								_Request=get_ongoing_challenges ) of

		% Process not started, wrong state, etc.:
		{ 'EXIT', ExitReason } ->
			trace_bridge:error_fmt( "Challenge not obtained: ~p.",
									[ ExitReason ] ),
			error;

		% If in 'idle' state:
		no_challenge ->
			no_challenge;

		ThumbprintMap ->
			ThumbprintMap

	end.








% Section for gen_statem API, in the 'state_functions' callback mode: the
% branching is done depending on the current state name (as atom), so (like with
% gen_fsm) we proceed per-state, then, for a given state, we handle all possible
% events.
%
% An event is handled by the Module:StateName(EventType, EventContent, Data)
% function, which is to return either {next_state, NextState, NewData, Actions}
% or {next_state, NextState, NewData}.

% 4 states are defined in turn below:
% - idle
% - pending
% - valid
% - finalize



% State 'idle', the initial state, typically used when awaiting for certificate
% requests to be triggered.
%
% idle(get_ongoing_challenges): nothing done
%
-spec idle( event_type(), event_content(), le_state() ) ->
				  state_callback_result().
% idle with request {create, BinDomain, OptionMap}: starts the certificate
% creation procedure.
%
% Starts a new certificate delivery process:
%  - create new account
%  - send a new order
%  - require authorization (returns challenges list)
%  - initiate chosen challenge
%
% Transition to:
%  - 'idle' if process failed
%  - 'pending' waiting for challenges to be complete
%
idle( _EventType=enter, _PreviousState, _Data ) ->
	trace_bridge:trace_fmt( "[~w] Entering the 'idle' state.", [ self() ] ),
	keep_state_and_data;

idle( _EventType={ call, From },
	  _EventContentMsg=_Request={ create, BinDomain, OptionMap },
	  _Data=LEState=#le_state{ directory_map=DirMap, agent_private_key=PrivKey,
							   jws=Jws, nonce=Nonce } ) ->

	trace_bridge:trace_fmt( "[~w] While idle: received a certificate creation "
		"request for domain '~s'.", [ self(), BinDomain ] ),

	% Ex: 'http-01', 'tls-sni-01', etc.:
	ChallengeType = maps:get( challenge, OptionMap, _DefaultChlg='http-01' ),

	case ChallengeType of

		'http-01' ->
			ok;

		OtherChallengeType ->
			throw( { unsupported_challenge_type, OtherChallengeType } )

	end,

	{ AccountDecodedJsonMap, AccountLocationUri, AccountNonce } =
		letsencrypt_api:create_acme_account( DirMap, PrivKey,
							 Jws#jws{ nonce=Nonce }, OptionMap, LEState ),

	% Payload decoded from JSON in AccountDecodedJsonMap will be like:
	%
	% #{<<"contact">> => [],
	%   <<"createdAt">> => <<"2020-10-14T10:08:04.774555017Z">>,
	%   <<"initialIp">> => <<"xx.xx.xx.xx">>,
	%   <<"key">> =>
	%      #{<<"e">> => <<"ATAB">>,<<"kty">> => <<"RSA">>,
	%        <<"n">> =>
	%            <<"3dPhjJ[...]">>},
	%   <<"status">> => <<"valid">>}

	% AccountLocationUri will be like:
	% "https://acme-staging-v02.api.letsencrypt.org/acme/acct/16210968"

	case maps:get( <<"status">>, AccountDecodedJsonMap ) of

		<<"valid">> ->
			ok;

		AccountUnexpectedStatus ->
			throw( { unexpected_status, AccountUnexpectedStatus,
					 account_creation } )

	end,

	AccountKeyAsMap = maps:get( <<"key">>, AccountDecodedJsonMap ),

	AccountKey = letsencrypt_tls:map_to_key( AccountKeyAsMap ),

	%trace_bridge:trace_fmt( "[~w] The obtained ACME account key is:~n  ~p",
	%						[ self(), AccountKey ] ),

	trace_bridge:trace_fmt( "[~w] ACME account key obtained.", [ self() ] ),

	% Apparently a difference JWS then:
	AccountJws = #jws{ alg=Jws#jws.alg, kid=AccountLocationUri,
					   nonce=AccountNonce },

	% Subject Alternative Names:
	Sans = maps:get( san, OptionMap, _DefaultSans=[] ),

	BinSans = text_utils:strings_to_binaries( Sans ),

	BinDomains = [ BinDomain | BinSans ],

	{ OrderDecodedJsonMap, OrderLocationUri, OrderNonce } =
		letsencrypt_api:request_new_certificate( DirMap, BinDomains, PrivKey,
									 AccountJws, OptionMap, LEState ),

	case maps:get( <<"status">>, OrderDecodedJsonMap ) of

		<<"pending">> ->
			ok;

		% If one was already created recently:
		<<"ready">> ->
			ok;

		CertUnexpectedStatus ->
			throw( { unexpected_status, CertUnexpectedStatus,
					 certificate_ordering } )

	end,

	% We need to keep trace of order location:
	LocOrder = OrderDecodedJsonMap#{ <<"location">> => OrderLocationUri },

	AuthLEState = LEState#le_state{ domain=BinDomain, jws=AccountJws,
		account_key=AccountKey, nonce=OrderNonce, sans=Sans },

	AuthUris = maps:get( <<"authorizations">>, OrderDecodedJsonMap ),

	AuthPair = perform_authorization( ChallengeType, AuthUris, AuthLEState ),

	{ NewStateName, Reply, NewUriChallengeMap, FinalNonce } =
			case AuthPair of

		{ UriChallengeMap, AuthNonce } ->
			{ pending, creation_pending, UriChallengeMap, AuthNonce };

		% Currently never happens:
		{ error, Err, ErrAuthNonce } ->
			{ idle, { creation_failed, Err }, _ResetChlgMap=#{}, ErrAuthNonce }

	end,

	FinalLEState = AuthLEState#le_state{ nonce=FinalNonce, order=LocOrder,
										 challenges=NewUriChallengeMap },

	trace_bridge:trace_fmt( "[~w][state] Switching from 'idle' to '~s'.",
							[ self(), NewStateName ] ),

	{ next_state, NewStateName, _NewData=FinalLEState,
	  _Action={ reply, From, Reply } };


idle( _EventType={ call, From },
	  _EventContentMsg=_Request=get_ongoing_challenges, _Data=_LEState ) ->

	trace_bridge:warning_fmt( "Received a get_ongoing_challenges request event "
		"from ~w while being idle.", [ From ] ),

	% Clearer than {next_state, idle, LEState, {reply, From,
	% _Reply=no_challenge}}:
	%
	{ keep_state_and_data, { reply, From, _Reply=no_challenge } };


% Possibly Request=stop:
idle( _EventType={ call, ServerRef }, _EventContentMsg=Request,
	  _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=idle, LEState );

idle( EventType, EventContentMsg, _LEState ) ->
	throw( { unexpected_event, EventType, EventContentMsg, { state, idle } } ).




% Management of the 'pending' state, when challenges are on-the-go.
%
% Returns a list of the challenges currently on-the-go with pre-computed
% thumbprints, i.e. a thumbprint_map().
%
pending( _EventType=enter, _PreviousState, _Data ) ->
	trace_bridge:trace_fmt( "[~w] Entering the 'pending' state.", [ self() ] ),
	keep_state_and_data;

pending( _EventType={ call, From }, _EventContentMsg=get_ongoing_challenges,
		 _Data=LEState=#le_state{ account_key=AccountKey,
								  challenges=TypeChallengeMap } ) ->

	trace_bridge:trace_fmt( "[~w] Getting ongoing challenges.", [ self() ] ),

	ThumbprintMap = maps:from_list( [ { Token,
		_Thumbprint=letsencrypt_jws:get_key_authorization( AccountKey, Token,
														   LEState ) }
		  || #{ <<"token">> := Token } <- maps:values( TypeChallengeMap ) ] ),

	trace_bridge:trace_fmt( "[~w] Returning from pending state challenge "
		"thumbprint map ~p.", [ self(), ThumbprintMap ] ),

	{ next_state, _SameState=pending, _Data=LEState,
	  _Action={ reply, From, _RetValue=ThumbprintMap } };


% Checks if all challenges are completed, and returns the (possibly new) current
% state.
%
% Switches to the 'valid' state iff all challenges are validated.
%
% Transitions to:
%	- 'pending' if at least one challenge is not completed yet
%	- 'valid' if all challenges are complete
%
pending( _EventType={ call, From }, _EventContentMsg=check_challenges_completed,
		 _Data=LEState=#le_state{
					  order=#{ <<"authorizations">> := AuthorizationsUris },
					  nonce=InitialNonce, agent_private_key=PrivKey, jws=Jws,
					  option_map=OptionMap } ) ->

	trace_bridge:trace_fmt( "[~w] Checking whether challenges are completed.",
							[ self() ] ),

	% Checking the status for each authorization URI:
	{ NextStateName, ResultingNonce } = lists:foldl(

		fun( AuthUri, _Acc={ AccStateName, AccNonce } ) ->

			{ AuthJsonMap, _Location, NewNonce } =
					letsencrypt_api:request_authorization( AuthUri, PrivKey,
						Jws#jws{ nonce=AccNonce }, OptionMap, LEState ),

			BinStatus = maps:get( <<"status">>, AuthJsonMap ),

			%trace_bridge:debug_fmt( "[~w] For auth URI ~s, received "
			%	"status '~s'.", [ self(), AuthUri, BinStatus ] ),

			NewStateName = case { AccStateName, BinStatus } of

				% Only status allowing to remain in 'valid' state:
				{ valid, <<"valid">> } ->
					valid;

				{ pending, _ } ->
					pending;

				{ _, <<"pending">> } ->
					pending;

				% Expecting AnyState to be generally 'valid':
				{ AnyState, <<"deactivated">> } ->
					trace_bridge:warning_fmt( "[~w] For auth URI ~s, switching "
						"from '~s' to unsupported 'deactivated' state.",
						[ self(), AnyState, AuthUri ] ),
					deactivated;

				{ AnyState, <<"expired">> } ->
					trace_bridge:warning_fmt( "[~w] For auth URI ~s, switching "
						"from '~s' to unsupported 'expired' state.",
						[ self(), AnyState, AuthUri ] ),
					expired;

				{ AnyState, <<"revoked">> } ->
					trace_bridge:warning_fmt( "[~w] For auth URI ~s, switching "
						"from '~s' to unsupported 'revoked' state.",
						[ self(), AnyState, AuthUri ] ),
					revoked;

				{ AnyState, <<"invalid">> } ->
					trace_bridge:warning_fmt( "[~w] For auth URI ~s, switching "
						"from '~s' to unsupported 'invalid' state.",
						[ self(), AnyState, AuthUri ] ),
					invalid;

				% By default remains in the current state (including 'pending'):
				{ AccStateName, AnyBinStatus } ->
					trace_bridge:trace_fmt( "[~w] For auth URI ~s, staying "
						"in '~s' despite having received status '~p'.",
						[ self(), AuthUri, AccStateName, AnyBinStatus ] ),
					AccStateName;

				{ AnyOtherState, UnexpectedBinStatus } ->
					trace_bridge:error_fmt( "[~w] For auth URI ~s, "
						"while in '~s' state, received unexpected status '~p'.",
						[ self(), AuthUri, AnyOtherState,
						  UnexpectedBinStatus ] ),

					throw( { unexpected_auth_status, UnexpectedBinStatus,
							 self(), AnyOtherState, AuthUri } )

			end,

			{ NewStateName, NewNonce }

		end,
		_Acc0={ _InitialNextStateName=valid, InitialNonce },
		_List=AuthorizationsUris ),


	% Be nice to ACME server:
	case NextStateName of

		pending ->
			trace_bridge:debug_fmt( "[~w] Remaining in 'pending' state.",
									[ self() ] ),
			timer:sleep( 1000 );

		_ ->
			trace_bridge:debug_fmt( "[~w] Check resulted in switching from "
				"'pending' to '~s' state.", [ self(), NextStateName ] ),
			ok

	end,

	{ next_state, NextStateName,
	  _NewData=LEState#le_state{ nonce=ResultingNonce },
	  _Action={ reply, From, _RetValue=NextStateName } };


pending( _EventType={ call, From }, _EventContentMsg=_Request=switchTofinalize,
		 _Data=_LEState ) ->

	trace_bridge:trace_fmt( "[~w] Received, while in 'pending' state, "
		"request '~s' from ~w, currently ignored.", [ self(), From ] ),

	% { next_state, finalize, ...}?

	keep_state_and_data;

pending( _EventType={ call, ServerRef }, _EventContentMsg=Request,
		 _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=pending,
								LEState );

pending( EventType, EventContentMsg, _LEState ) ->

	trace_bridge:warning_fmt( "[~w] Received, while in 'pending' state, "
		"event type '~p' and content message '~p'.",
		[ self(), EventType, EventContentMsg ] ),

	throw( { unexpected_event, EventType, EventContentMsg,
			 { state, pending } } ).



% Management of the 'valid' state.
%
% When challenges have been successfully completed, finalizes the ACME order and
% generates TLS certificate.
%
% Returns Status, the order status.
%
% Transitions to 'finalize' state.
%
valid( _EventType=enter, _PreviousState, _Data ) ->
	trace_bridge:trace_fmt( "[~w] Entering the 'valid' state.", [ self() ] ),
	keep_state_and_data;

valid( _EventType={ call, _ServerRef=From },
	   _EventContentMsg=_Request=switchTofinalize,
	   _Data=LEState=#le_state{ mode=Mode, domain=BinDomain, sans=SANs,
			cert_dir_path=BinCertDirPath, order=OrderDirMap,
			agent_private_key=PrivKey, jws=Jws, nonce=Nonce,
			option_map=OptionMap } ) ->

	trace_bridge:trace_fmt( "[~w] Trying to switch to finalize while being "
							"in the 'valid' state.", [ self() ] ),

	challenge_destroy( Mode, LEState ),

	KeyFilename = text_utils:binary_to_string( BinDomain ) ++ ".key",

	% KeyFilePath is required for CSR generation:
	CreatedTLSPrivKey = letsencrypt_tls:create_private_key(
						  { new, KeyFilename }, BinCertDirPath ),

	Csr = letsencrypt_tls:get_cert_request( BinDomain, BinCertDirPath, SANs ),

	{ FinOrderDirMap, _BinLocUri, FinNonce } = letsencrypt_api:finalize_order(
		OrderDirMap, Csr, PrivKey, Jws#jws{ nonce=Nonce }, OptionMap, LEState ),

	BinStatus = maps:get( <<"status">>, FinOrderDirMap ),

	% Expected to be 'finalize' sooner or later:
	ReadStateName = letsencrypt_api:binary_to_status( BinStatus ),

	% Update location in finalized order:
	LocOrderDirMap = FinOrderDirMap#{
				   <<"location">> => maps:get( <<"location">>, OrderDirMap ) },

	FinalLEState = LEState#le_state{ order=LocOrderDirMap,
		agent_key_file_path=CreatedTLSPrivKey#tls_private_key.file_path,
		nonce=FinNonce },

	trace_bridge:trace_fmt( "[~w][state] Switching from 'valid' to 'finalize' "
		"(after having read '~s').", [ self(), ReadStateName ] ),

	{ next_state, _NewStateName=finalize, _NewData=FinalLEState,
	  _Action={ reply, From, _Reply=ReadStateName } };


valid( _EventType={ call, ServerRef }, _EventContentMsg=Request,
	  _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=valid,
								LEState );

valid( EventType, EventContentMsg, _LEState ) ->
	throw( { unexpected_event, EventType, EventContentMsg,
			 { state, valid }, self() } ).



% Management of the 'finalize' state.
%
% When order is being finalized, and certificate generation is ongoing.
%
% Waits for certificate generation being complete (order status == 'valid').
%
% Returns the order status.
%
% Transitions to:
%   state 'processing' : still ongoing
%   state 'valid'      : certificate is ready
%
finalize( _EventType=enter, _PreviousState, _Data ) ->
	trace_bridge:trace_fmt( "[~w] Entering the 'finalize' state.", [ self() ] ),
	keep_state_and_data;

finalize( _EventType={ call, _ServerRef=From },
		  _EventContentMsg=_Request=manageCreation,
		  _Data=LEState=#le_state{ order=OrderMap, domain=BinDomain,
			  %agent_key_file_path=KeyFilePath,
			  cert_dir_path=BinCertDirPath,
			  agent_private_key=PrivKey, jws=Jws, nonce=Nonce,
			  option_map=OptionMap } ) ->

	%trace_bridge:trace_fmt( "[~w] Getting progress of creation procedure "
	%	"based on order map:~n   ~p.", [ self(), OrderMap ] ),

	trace_bridge:trace_fmt( "[~w] Getting progress of creation procedure "
							"based on order map.", [ self() ] ),

	Loc = maps:get( <<"location">>, OrderMap ),

	{ NewOrderMap, _NullLoc, OrderNonce } = letsencrypt_api:get_order( Loc,
					PrivKey, Jws#jws{ nonce=Nonce }, OptionMap, LEState ),

	BinStatus = maps:get( <<"status">>, NewOrderMap ),

	ReadStatus = letsencrypt_api:binary_to_status( BinStatus ),

	{ Reply, NewStateName, NewNonce, NewJws } = case ReadStatus of

		processing ->
			trace_bridge:trace_fmt( "[~w] Certificate creation still in "
				"progress on server.", [ self() ] ),
			{ creation_in_progress, finalize, OrderNonce, Jws };

		% Downloads certificate and saves it into file.
		%
		% Transitions to state 'idle': fsm complete, going back to initial
		% state.
		%
		valid ->
			trace_bridge:trace_fmt( "[~w] Finalizing certificate creation now.",
									[ self() ] ),

			%BinKeyFilePath = text_utils:string_to_binary( KeyFilePath ),

			% Downloads certificate:
			{ BinCert, DownloadNonce } = letsencrypt_api:get_certificate(
				OrderMap, PrivKey, Jws#jws{ nonce=OrderNonce }, OptionMap,
				LEState ),

			Domain = text_utils:binary_to_string( BinDomain ),

			CertFilePath = letsencrypt_tls:write_certificate( Domain, BinCert,
															  BinCertDirPath ),

			BinCertFilePath = text_utils:string_to_binary( CertFilePath ),

			trace_bridge:trace_fmt( "[~w] Certificate generated in ~s, "
				"switching from 'finalize' to the 'idle' state.",
				[ self(), BinCertFilePath ] ),

			% Shall we continue with the same account for any next operation?
			% No, and the current JWS would not be suitable for that (ex: not
			% having the public key of that LEEC agent), and anyway we prefer
			% creating a new account each time a new operation is performed (as
			% ~90 days may elapse between two operations). So:
			%
			AgentKeyJws = letsencrypt_jws:init( PrivKey ),

			% Safer, not wasting idle connections, bound to fail after some time
			% anyway:
			%
			letsencrypt_api:close_tcp_connections(),

			{ { certificate_ready, BinCertFilePath }, idle,
			  DownloadNonce, AgentKeyJws };


		% Like for 'processing', yet with a different trace:
		OtherStatus ->
			trace_bridge:warning_fmt( "[~w] Unexpected read status while "
				"finalizing: '~s' (ignored).", [ self(), OtherStatus ] ),
			{ creation_in_progress, finalize, OrderNonce, Jws }

	end,

	NewLEState = LEState#le_state{ order=NewOrderMap, jws=NewJws,
								   nonce=NewNonce },

	{ next_state, NewStateName, _NewData=NewLEState,
	  _Action={ reply, From, Reply } };


finalize( _EventType={ call, ServerRef }, _EventContentMsg=Request,
		  _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=finalize,
								LEState );


finalize( UnexpectedEventType, EventContentMsg, _LEState ) ->

	trace_bridge:error_fmt( "Unknown event ~p (content: ~p) in "
		"finalize status.",	[ UnexpectedEventType, EventContentMsg ] ),

	%{ reply, { error, UnexpectedEventType }, finalize, LEState }.

	throw( { unexpected_event, UnexpectedEventType, EventContentMsg,
			 { state, finalize } } ).




% Callback section.




% Handles the specified call in the same way for all states.
%
% (helper)
%
-spec handle_call_for_all_states( server_ref(), request(), state_name(),
								  le_state() ) -> state_callback_result().
handle_call_for_all_states( ServerRef, _Request=get_status, StateName,
							_LEState ) ->

	trace_bridge:debug_fmt( "[~w] Returning current status: '~s'.",
							[ ServerRef, StateName ] ),

	Res = StateName,

	{ keep_state_and_data, _Actions={ reply, _From=ServerRef, Res } };


handle_call_for_all_states( ServerRef, _Request=stop, StateName,
							LEState=#le_state{ mode=Mode } ) ->

	trace_bridge:debug_fmt( "[~w] Received a stop request from ~s state.",
							[ ServerRef, StateName ] ),

	challenge_destroy( Mode, LEState ),

	% Stopping is just returning back to idle (no action):

	%{ stop_and_reply, _Reason, _Reply={ reply, ServerRef, ok },
	%   _Data=LEState }.

	{ next_state, _NextState=idle, _NewData=LEState };


handle_call_for_all_states( ServerRef, Request, StateName, _LEState ) ->

	trace_bridge:error_fmt( "[~w] Received an unexpected request, ~p, "
		"while in state ~p.", [ ServerRef, Request, StateName ] ),

	throw( { unexpected_request, Request, ServerRef, StateName } ).



% Standard callbacks:

terminate( _, _, _ ) ->
	ok.


code_change( _, StateName, LEState, _ ) ->
	{ ok, StateName, LEState }.




% Helpers.


% Parses the start/1 options.
%
% Available options are:
%  - staging: runs in staging environment (otherwise running in production one)
%  - mode: webroot, slave or standalone
%  - agent_key_file_path: to reuse an existing agent TLS key
%  - cert_dir_path: path to read/save TLS certificates, keys and CSR requests
%  - webroot_dir_path: the webroot directory, in a conventional subdirectory of
%  which challenge answers shall be written so that the ACME server can download
%  them
%  - port: the TCP port at which the corresponding webserver shall be available,
%  in standalone mode
%  - http_timeout: timeout for ACME API requests (in seconds)
%
% Returns LEState (type record 'le_state') filled with corresponding, checked
% option values.
%
-spec get_options( [ user_option() ], le_state() ) -> le_state().
get_options( _Opts=[], LEState ) ->
	LEState;

get_options( _Opts=[ staging | T ], LEState ) ->
	get_options( T, LEState#le_state{ env=staging } );

get_options( _Opts=[ { mode, Mode } | T ], LEState ) ->
	case lists:member( Mode, [ webroot, slave, standalone ] ) of

		true ->
			ok;

		false ->
			throw( { invalid_leec_mode, Mode } )

	end,
	get_options( T, LEState#le_state{ mode=Mode } );

get_options( _Opts=[ { agent_key_file_path, KeyFilePath } | T ], LEState ) ->
	AgentKeyFilePath = text_utils:ensure_string( KeyFilePath ),
	case file_utils:is_existing_file_or_link( AgentKeyFilePath ) of

		true ->
			get_options( T, LEState#le_state{
							  agent_key_file_info=AgentKeyFilePath } );

		false ->
			throw( { non_existing_agent_key_file, AgentKeyFilePath } )

	end;


get_options( _Opts=[ { cert_dir_path, BinCertDirPath } | T ], LEState )
  when is_binary( BinCertDirPath ) ->
	case file_utils:is_existing_directory_or_link( BinCertDirPath ) of

		true ->
			get_options( T, LEState#le_state{ cert_dir_path=BinCertDirPath } );

		false ->
			throw( { non_existing_certificate_directory,
					 text_utils:binary_to_string( BinCertDirPath ) } )

	end;

get_options( _Opts=[ { cert_dir_path, CertDirPath } | T ], LEState ) ->
	BinCertDirPath = text_utils:string_to_binary( CertDirPath ),
	get_options( [ { cert_dir_path, BinCertDirPath } | T ], LEState );


get_options( _Opts=[ { webroot_dir_path, BinWebDirPath } | T ], LEState )
  when is_binary( BinWebDirPath ) ->
	case file_utils:is_existing_directory_or_link( BinWebDirPath ) of

		true ->
			get_options( T,
						 LEState#le_state{ webroot_dir_path=BinWebDirPath } );

		false ->
			throw( { non_existing_webroot_directory,
					 text_utils:binary_to_string( BinWebDirPath ) } )

	end;

get_options( _Opts=[ { webroot_dir_path, WebDirPath } | T ], LEState ) ->
	BinWebDirPath = text_utils:string_to_binary( WebDirPath ),
	get_options( [ { webroot_dir_path, BinWebDirPath } | T ], LEState );


get_options( _Opts=[ { port, Port } | T ], LEState ) when is_integer( Port ) ->
	get_options( T, LEState#le_state{ port=Port } );

get_options( _Opts=[ { port, Port } | _T ], _LEState ) ->
	throw( { invalid_standalone_tcp_port, Port } );

get_options( _Opts=[ { http_timeout, Timeout } | T ], LEState )
  when is_integer( Timeout ) ->
	get_options( T, LEState#le_state{
				  option_map=#{ netopts => #{ timeout => Timeout } } } );

get_options( _Opts=[ { http_timeout, Timeout } | _T ], _LEState ) ->
	throw( { invalid_http_timeout, Timeout } );

get_options( _Opts=[ Unexpected | _T ], _LEState ) ->
	trace_bridge:error_fmt( "Invalid LEEC option specified: ~p.",
							[ Unexpected ] ),
	throw( { invalid_leec_option, Unexpected } ).



% Setups the context of chosen mode.
-spec setup_mode( le_state() ) -> le_state().
setup_mode( #le_state{ mode=webroot, webroot_dir_path=undefined } ) ->
	trace_bridge:error( "Missing 'webroot_dir_path' parameter." ),
	throw( webroot_dir_path_missing );

setup_mode( LEState=#le_state{ mode=webroot,
							   webroot_dir_path=BinWebrootPath } ) ->

	ChallengeDirPath =
		file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

	% TODO: check directory is writable.
	file_utils:create_directory_if_not_existing( ChallengeDirPath,
												 create_parents ),

	LEState;

% Already checked:
setup_mode( LEState=#le_state{ mode=standalone, port=Port } )
  when is_integer( Port ) ->
	% TODO: check port is unused?
	LEState;

setup_mode( LEState=#le_state{ mode=slave } ) ->
	LEState;

% Every other mode value is invalid:
setup_mode( #le_state{ mode=Mode } ) ->
	trace_bridge:error_fmt( "Invalid '~p' mode.", [ Mode ] ),
	throw( { invalid_mode, Mode } ).



% Loops a few times on authorization check until challenges are all validated
% (with increasing waiting times after each attempt); if successful, the FSM
% should be in 'valid' state when returning.
%
% Returns:
%   - {error, timeout} if failed after X loops
%   - {error, Err} if another error
%   - 'ok' if succeed
%
-spec wait_challenges_valid( fsm_pid() ) -> base_status().
wait_challenges_valid( FsmPid ) ->
	Count = 20,
	wait_challenges_valid( FsmPid, Count, Count ).


% (helper)
-spec wait_challenges_valid( fsm_pid(), count(), count() ) -> base_status().
wait_challenges_valid( _FsmPid, _Count=0, _MaxCount ) ->
	{ error, timeout };

wait_challenges_valid( FsmPid, Count, MaxCount ) ->

	% This request triggers a check and possibly a state transition, the
	% (possibly new) current state being then returned:
	%
	case gen_statem:call( _ServerRef=FsmPid,
				_Request=check_challenges_completed, ?base_timeout ) of

		valid ->
			trace_bridge:debug_fmt( "FSM ~w reported that challenges are "
									"completed.", [ FsmPid ] ),
			ok;

		pending ->
			trace_bridge:debug_fmt( "FSM ~w reported that challenges are "
									"still pending.", [ FsmPid ] ),
			timer:sleep( 500 * ( MaxCount - Count + 1 ) ),
			wait_challenges_valid( FsmPid, Count - 1, MaxCount );

		{ _Other, Error } ->
			{ error, Error };

		UnexpectedState ->
			throw( { unexpected_checked_state, UnexpectedState } )

	end.



% Waits until the certification creation is reported as completed.
%
% Returns:
%   - {error, timeout} if failed after X loops
%   - {error, Err} if another error
%   - {'ok', Response} if succeed
%
-spec wait_creation_completed( fsm_pid(), count() ) ->
		  { 'ok', map() } | { 'error', 'timeout' | any() }.
wait_creation_completed( FsmPid, C ) ->

	trace_bridge:debug_fmt( "[~w] Waiting for the completion of the "
		"certificate creation...", [ FsmPid ] ),

	wait_creation_completed( FsmPid, C, C ).



% Waits until specified status is read.
%
% (helper)
%
-spec wait_creation_completed( fsm_pid(), count(), count() ) ->
					 { 'certificate_ready', bin_file_path() }
				   | { 'error', 'timeout' | any() }.
wait_creation_completed( _FsmPid, _Count=0, _Max ) ->
	{ error, timeout };

wait_creation_completed( FsmPid, Count, Max ) ->

	case gen_statem:call( _ServerRef=FsmPid, _Req=manageCreation,
						  ?base_timeout ) of

		Reply={ certificate_ready, BinCertFilePath } ->
			trace_bridge:debug_fmt( "End of waiting for creation of '~s': "
				"read target status 'finalize' for ~w.",
				[ BinCertFilePath, FsmPid ] ),
			Reply;

		creation_in_progress ->
			trace_bridge:debug_fmt( "Still waiting for creation from ~w.",
									[ FsmPid ] ),
			timer:sleep( 500 * ( Max - Count + 1 ) ),
			wait_creation_completed( FsmPid, Count-1, Max );

		% Not expected to ever happen:
		Any ->
			trace_bridge:warning_fmt( "Received unexpected '~p' for ~w while "
				"waiting for creation (ignored).", [ Any, FsmPid ] ),
			wait_creation_completed( FsmPid, Count-1, Max )

	end.



% Performs ACME authorization based on selected challenge initialization.
-spec perform_authorization( challenge_type(), [ bin_uri() ], le_state() ) ->
						  { uri_challenge_map(), nonce() }.
perform_authorization( ChallengeType, AuthUris,
					   LEState=#le_state{ mode=Mode } ) ->

	trace_bridge:trace_fmt( "[~w] Starting authorization procedure with "
		"challenge type '~s' (mode: ~s).", [ self(), ChallengeType, Mode ] ),

	BinChallengeType = text_utils:atom_to_binary( ChallengeType ),

	{ UriChallengeMap, Nonce } = perform_authorization_step1( AuthUris,
				BinChallengeType, LEState, _UriChallengeMap=#{} ),

	%trace_bridge:debug_fmt( "[~w] URI challenge map after step 1:~n  ~p.",
	%						[ self(), UriChallengeMap ] ),

	% UriChallengeMap is like:
	%
	%  #{<<"https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/142509381">> =>
	%   #{<<"status">> => <<"pending">>,
	%     <<"token">> => <<"qVTq6gQWZO4Dt4gUmnaTQdwTRkpaSnMiRx8L7Grzhl8">>,
	%     <<"type">> => <<"http-01">>,
	%     <<"url">> =>
	%         <<"https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/142509381/-Axkdw">>}}.

	init_for_challenge_type( ChallengeType, Mode, LEState, UriChallengeMap ),

	NewNonce = perform_authorization_step2( maps:to_list( UriChallengeMap ),
								 LEState#le_state{ nonce=Nonce } ),

	{ UriChallengeMap, NewNonce }.



% Requests authorizations based on specified challenge type and URIs: for each
% challenge type (ex: http-01, dns-01, etc.), a challenge is proposed.
%
% At least in some cases, a single authorization URI is actually listed.
%
% Returns:
%   {ok, Challenges, Nonce}
%		- Challenges is map of Uri -> Challenge, where Challenge is of
%		ChallengeType type
%		- Nonce is a new valid replay-nonce
%
-spec perform_authorization_step1( [ bin_uri() ], bin_challenge_type(),
		le_state(), uri_challenge_map() ) -> { uri_challenge_map(), nonce() }.
perform_authorization_step1( _AuthUris=[], _BinChallengeType,
							 #le_state{ nonce=Nonce }, UriChallengeMap ) ->
	{ UriChallengeMap, Nonce };

perform_authorization_step1( _AuthUris=[ AuthUri | T ], BinChallengeType,
			LEState=#le_state{ nonce=Nonce, agent_private_key=PrivKey,
							   jws=Jws, option_map=OptionMap },
			UriChallengeMap ) ->

	% Ex: AuthUri =
	%  "https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/133572032"

	{ AuthMap, _LocUri, NewNonce } = letsencrypt_api:request_authorization(
		AuthUri, PrivKey, Jws#jws{ nonce=Nonce }, OptionMap, LEState ),

	%trace_bridge:debug_fmt( "[~w] Step 1: authmap returned for URI '~s':"
	%						"~n  ~p.", [ self(), AuthUri, AuthMap ] ),

	% Ex: AuthMap =
	% #{<<"challenges">> =>
	%	   [#{<<"status">> => <<"pending">>,
	%		  <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
	%		  <<"type">> => <<"http-01">>,
	%		  <<"url">> =>
	% <<"https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/133572032/Zu9ioQ">>},
	%		#{<<"status">> => <<"pending">>,
	%		  <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
	%		  <<"type">> => <<"dns-01">>,
	%		  <<"url">> =>
	% <<"https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/133572032/u9WbrQ">>},
	%		#{<<"status">> => <<"pending">>,
	%		  <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
	%		  <<"type">> => <<"tls-alpn-01">>,
	%		  <<"url">> =>
	% <<"https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/133572032/_WS56A">>}],
	%   <<"expires">> => <<"2020-10-18T14:48:11Z">>,
	%   <<"identifier">> =>
	%	   #{<<"type">> => <<"dns">>,<<"value">> => <<"www.foobar.org">>},
	%   <<"status">> => <<"pending">>}.

	case maps:get( <<"status">>, AuthMap ) of

		<<"pending">> ->
			ok;

		% Should a previous request have already been performed:
		<<"valid">> ->
			ok;

		AuthUnexpectedStatus ->
			throw( { unexpected_status, AuthUnexpectedStatus,
					 authorization_step1 } )

	end,


	% Retains only the specified challenge type (cannot be a list
	% comprehension):
	%
	[ Challenge ] = lists:filter(

		fun( ChlgMap ) ->
			maps:get( <<"type">>, ChlgMap,
					  _Default=never_match ) =:= BinChallengeType
		end,

		_List=maps:get( <<"challenges">>, AuthMap ) ),

	perform_authorization_step1( T, BinChallengeType,
		LEState#le_state{ nonce=NewNonce },
		UriChallengeMap#{ AuthUri => Challenge } ).



% Second step of the authorization process, executed after challenge
% initialization.
%
% Notifies the ACME server the challenges are good to proceed, returns an
% updated nonce.
%
-spec perform_authorization_step2( [ { bin_uri(), challenge() } ],
								   le_state()) -> nonce().
perform_authorization_step2( _Pairs=[], #le_state{ nonce=Nonce } ) ->
	Nonce;

perform_authorization_step2( _Pairs=[ { Uri, Challenge } | T ],
			LEState=#le_state{ nonce=Nonce, agent_private_key=AgentPrivKey,
							   jws=Jws, option_map=OptionMap } ) ->

	{ Resp, _Location, NewNonce } =
		letsencrypt_api:notify_ready_for_challenge( Challenge, AgentPrivKey,
								Jws#jws{ nonce=Nonce }, OptionMap, LEState ),

	case maps:get( <<"status">>, Resp ) of

		<<"pending">> ->
			ok;

		% Should a previous request have already been performed:
		<<"valid">> ->
			ok;

		AuthUnexpectedStatus ->
			throw( { unexpected_status, AuthUnexpectedStatus,
					 authorization_step2, Uri } )

	end,

	perform_authorization_step2( T, LEState#le_state{ nonce=NewNonce } ).



% Initializes the local configuration to serve the specified challenge type.
%
% Depends on challenge type and mode.
%
-spec init_for_challenge_type( challenge_type(), le_mode(), le_state(),
							   uri_challenge_map() ) -> void().
init_for_challenge_type( _ChallengeType='http-01', _Mode=webroot,
		LEState=#le_state{ webroot_dir_path=BinWebrootPath,
						   account_key=AccountKey },
		UriChallengeMap ) ->

	[ begin

		ChlgWebDir = file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

		file_utils:create_directory_if_not_existing( ChlgWebDir ),

		ChlgWebPath = file_utils:join( ChlgWebDir, Token ),

		Thumbprint = letsencrypt_jws:get_key_authorization( AccountKey, Token,
															LEState ),

		% Hopefully the default modes are fine:
		file_utils:write_whole( ChlgWebPath, Thumbprint, _Modes=[] )

	  end || #{ <<"token">> := Token } <- maps:values( UriChallengeMap ) ];


init_for_challenge_type( _ChallengeType, _Mode=slave, _LEState,
						 _UriChallengeMap ) ->
	ok;

init_for_challenge_type( ChallengeType, _Mode=standalone,
			LEState=#le_state{ port=Port, domain=Domain, account_key=AccntKey },
			UriChallengeMap ) ->

	%trace_bridge:debug_fmt( "Init standalone challenge for ~p.",
	%                        [ ChallengeType ] ),

	case ChallengeType of

		'http-01' ->
			% elli webserver callback args is:
			% #{Domain => #{
			%     Token => Thumbprint,
			%     ...
			% }}
			%

			% Iterating on values:
			Thumbprints = maps:from_list(
				[ { Token, letsencrypt_jws:get_key_authorization( AccntKey,
														  Token, LEState ) }
				  || #{ <<"token">> := Token }
						 <- maps:values( UriChallengeMap ) ] ),

			{ ok, _ } = elli:start_link([
				{ name, { local, letsencrypt_elli_listener } },
				{ callback, letsencrypt_elli_handler },
				{ callback_args, [ #{ Domain => Thumbprints } ] },
				% If is not 80, a priori should not work as ACME to look for it:
				{ port, Port } ] );

		%'tls-sni-01' ->
		%   TODO

		_ ->
			trace_bridge:error_fmt( "Standalone mode: unsupported ~p challenge "
									"type.", [ ChallengeType ] ),

			throw( { unsupported_challenge_type, ChallengeType, standalone } )

	end.



% Cleans up challenge context after it has been fullfilled (with success or
% not); in:
% - 'webroot' mode: delete token file
% - 'standalone' mode: stop internal webserver
% - 'slave' mode: nothing to do
%
-spec challenge_destroy( le_mode(), le_state() ) -> void().
challenge_destroy( _Mode=webroot, #le_state{ webroot_dir_path=BinWPath,
											 challenges=UriChallengeMap } ) ->

	[ begin

		  ChalWebPath = file_utils:join(
						[ BinWPath, ?webroot_challenge_path, Token ] ),

		  file_utils:remove_file( ChalWebPath )

	  end || #{ <<"token">> := Token } <- maps:values( UriChallengeMap ) ];


challenge_destroy( _Mode=standalone, _LEState ) ->
	% Stop http server:
	elli:stop( letsencrypt_elli_listener );


challenge_destroy( _Modeslave, _LEState ) ->
	ok.
