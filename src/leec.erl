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


% @doc <b>Main module of LEEC</b>, the Ceylan Let's Encrypt Erlang fork; see
% [http://leec.esperide.org] for more information.
%
% Original 'Let's Encrypt Erlang' application:
% [https://github.com/gbour/letsencrypt-erlang].
%
-module(leec).


% Original work:
-author("Guillaume Bour (guillaume at bour dot cc)").

% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com").


% Replaces the deprecated gen_fsm; we use here the 'state_functions' callback
% mode, so:
%
%  - events are handled by one callback function *per state*
%
%  - state names must be atom-only
%
-behaviour(gen_statem).


% This is a (passive) application:
-behaviour(application).


% Public API:
-export([ get_ordered_prerequisites/0,
		  start/1, start/2,
		  get_default_cert_request_options/0,
		  get_default_cert_request_options/1,
		  obtain_certificate_for/2, obtain_certificate_for/3, stop/1 ]).


% For testing purpose:
-export([ get_ongoing_challenges/1, send_ongoing_challenges/2,
		  get_agent_key_path/1 ]).


% For spawn purpose:
-export([ obtain_cert_helper/4 ]).


% FSM gen_statem base API:
-export([ init/1, callback_mode/0, terminate/3, code_change/4 ]).


% FSM state-corresponding callbacks:
-export([ idle/3, pending/3, valid/3, finalize/3, invalid/3 ]).


% For myriad_spawn*:
-include_lib("myriad/include/spawn_utils.hrl").


% Implementation notes:
%
% Multiple FSM (Finite State Machines) can be spawned, for parallel certificate
% management. Not registered as not a singleton anymore.

% Similarly, no more ETS-based connection pool, as it would be shared between
% concurrent FSMs, whereas eaci connection is private to a given FSM. Instead an
% (explicit) TCP cache is managed per-FSM.

% URI format compatible with the shotgun library.
%
% The netopts map (in the option map) possibly just contains a time-out, or
% maybe SSL options; it is a parameter directly needed as such by
% shotgun:post/5.


-type bin_domain() :: net_utils:bin_fqdn().

-type domain() :: net_utils:string_fqdn() | bin_domain().


-type le_mode() :: 'webroot' | 'slave' | 'standalone'.
% Three ways of interfacing LEEC with user code.


-type fsm_pid() :: pid().
% The PID of a LEEC FSM.


-type certificate_provider() :: 'letsencrypt'.
% Others may be added in the future.


-type challenge_type() :: 'http-01'
						| 'tls-sni-01'
						| 'dns-01'.
% Note: only the 'http-01' challenge type is supported currently.


-type bin_challenge_type() :: bin_string().
% Challenge type, as a binary string.


% Supposedly:
-type token() :: ustring().

-type thumbprint() :: json().
% A JSON-encoded key.


-type thumbprint_map() :: table( token(), thumbprint() ).
% Associating tokens with keys.


-type tcp_connection_cache() :: table( { net_utils:protocol_type(),
		net_utils:string_host_name(), net_utils:tcp_port() },
		shotgun:connection() ).
% For the reuse of TCP connections to the ACME server.


-type string_uri() :: ustring().

-type bin_uri() :: binary().

-type uri() :: string_uri() | bin_uri().


% ACME_BASE below can be for example
% https://acme-staging-v02.api.letsencrypt.org, ACME_COMM being
% https://community.letsencrypt.org.


-type challenge() :: table:table( bin_string(), bin_string() ).
% All known information regarding a challenge.
%
% As Key => example of associated value:
%
% - `<<"status">> => <<"pending">>'
%
% - `<<"token">> => <<"qVTx6gQWZO4Dt4gUmnaTQdwTRkpaSnMiRx8L7Grzhl8">>'
%
% - `<<"type">> => <<"http-01">>'
%
% - `<<"url">> =>
%     <<"ACME_BASE/acme/chall-v3/132509381/-Axkdw">>'
%
-type uri_challenge_map() :: table( bin_uri(), challenge() ).


-type type_challenge_map() :: table( challenge_type(), challenge() ).


-type start_option() :: 'staging'
					 | { 'mode', le_mode() }
					 | { 'key_file_path', any_file_path() }
					 | { 'cert_dir_path', any_directory_path() }
					 | { 'webroot_dir_path', any_directory_path() }
					 | { 'port', tcp_port() }
					 | { 'http_timeout', unit_utils:milliseconds() }.
% A user-specified LEEC start option.


-type cert_req_option_id() :: 'async' | 'callback' | 'netopts' | 'challenge'
							| 'sans' | 'json'.
% Certificate request options.


-type cert_req_option_map() :: table( cert_req_option_id(), term() ).
% Storing certificate request options.
%
% Known (atom) keys:
%
%  - async :: boolean() [if not defined, supposed true]
%
%  - callback :: fun/1
%
%  - netopts :: map() => #{ timeout => unit_utils:milliseconds(),
%                           ssl => [ ssl:client_option() ] }
%
%  - challenge_type :: challenge_type(), default being 'http-01'
%
%  - sans :: [ bin_san() ]
%
%  - json :: boolean() (not to be set by the user)


-type acme_operation() :: bin_string().
% ACME operations that may be triggered.
%
% Known operations:
%
% - `<<"newAccount">>'
%
% - `<<"newNonce">>'
%
% - `<<"newOrder">>'
%
% - `<<"revokeCert">>'


-type directory_map() :: table( acme_operation(), uri() ).
% ACME directory, converting operations to trigger into the URIs to access for
% them.


-type nonce() :: binary().
% An arbitrary binary that can be used just once in a cryptographic
% communication.


-type san() :: ustring().
% Subject Alternative Name, i.e. values to be associated with a security
% certificate using a subjectAltName field.
%
% See [https://en.wikipedia.org/wiki/Subject_Alternative_Name].

-type bin_san() :: bin_string().

-type any_san() :: san() | bin_san().


-type json_map_decoded() :: map().
% JSON element decoded as a map.


-type agent_key_file_info() :: { 'new', bin_file_path() } | bin_file_path().
% Information regarding the private key of the LEEC agent.
%
% (if 'new' is used, the path is supposed to be either absolute, or relative to
% the certificate directory)


-type bin_certificate() :: binary().
% A certificate, as a binary.


-type bin_key() :: binary().
% A key, as a binary.


-type bin_csr_key() :: bin_key().
% A CSR key, as a binary.


-type jws_algorithm() :: 'RS256'.


-type binary_b64() :: binary().
% A binary that is encoded in base 64.


-type key_auth() :: binary().
% Key authorization, a binary made of a token and of the hash of a key
% thumbprint, once b64-encoded.


% For the records introduced:
-include("leec.hrl").

-type tls_private_key() :: #tls_private_key{}.


-type tls_public_key() :: #tls_public_key{}.

-type jws() :: #jws{}.

-type certificate() :: #certificate{}.

-type le_state() :: #le_state{}.
% Needed by other LEEC modules.


-export_type([ bin_domain/0, domain/0, le_mode/0, fsm_pid/0,
			   certificate_provider/0, challenge_type/0, bin_challenge_type/0,
			   token/0, thumbprint/0, thumbprint_map/0, tcp_connection_cache/0,
			   string_uri/0, bin_uri/0, uri/0,
			   challenge/0, uri_challenge_map/0, type_challenge_map/0,
			   start_option/0, cert_req_option_id/0, cert_req_option_map/0,
			   acme_operation/0, directory_map/0, nonce/0,
			   san/0, bin_san/0, any_san/0,
			   json_map_decoded/0, agent_key_file_info/0,
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


-type server_ref() :: gen_statem:server_ref().
% Typically fsm_pid().


-type state_callback_result() ::
		gen_statem:state_callback_result( gen_statem:action() ).


-type status() :: 'pending' | 'processing' | 'valid' | 'invalid' | 'revoked'.
% FSM status (corresponding to state names).


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

-type bin_file_path() :: file_utils:bin_file_path().
-type any_file_path() :: file_utils:any_file_path().

-type any_directory_path() :: file_utils:any_directory_path().


-type tcp_port() :: net_utils:tcp_port().

-type json() :: json_utils:json().

-type application_name() :: otp_utils:application_name().



% Public API.


% @doc Returns an (ordered) list of the LEEC prerequisite OTP applications, to
% be started in that order.
%
% Notes:
%
% - not listed here (not relevant for that use case): elli, getopt, yamerl,
% erlang_color
%
% - jsx preferred over jiffy; yet neither needs to be initialised as an
% application
%
% - no need to start myriad either
%
-spec get_ordered_prerequisites() -> [ application_name() ].
get_ordered_prerequisites() ->
	cond_utils:if_set_to( myriad_httpc_backend, shotgun,
						  [ shotgun ], _ThenNativeHttpc=[] ).


% @doc Starts a (non-bridged) instance of the LEEC service FSM.
-spec start( [ start_option() ] ) -> { 'ok', fsm_pid() } | error_term().
start( StartOptions ) ->
	start( StartOptions, _MaybeBridgeSpec=undefined ).


% @doc Starts an instance of the LEEC service FSM, possibly with a trace bridge.
-spec start( [ start_option() ], maybe( trace_bridge:bridge_spec() ) ) ->
				{ 'ok', fsm_pid() } | error_term().
start( StartOptions, MaybeBridgeSpec ) ->

	% If a trace bridge is specified, we use it both for the current (caller)
	% process and the ones it creates, i.e. the associated FSM and, possibly,
	% the helper process (if asynchronous operations are requested).

	% First this caller process:
	trace_bridge:register_if_not_already( MaybeBridgeSpec ),

	% shotgun not being listed in LEEC's .app file anymore (otherwise it would
	% be started even if native_httpc had been preferred), it is not
	% automatically started; this is thus done here (elli also is not wanted
	% anymore by default, it might be started only iff in standalone mode):
	%
	% Intentionally no default token defined:
	cond_utils:switch_set_to( myriad_httpc_backend, [

		{ shotgun,
			begin
			  trace_bridge:info_fmt( "Starting LEEC (shotgun-based), with "
				  "following start options:~n  ~p.", [ StartOptions ] ),
			  [ { ok, _Started } = application:ensure_all_started( A )
				  || A <- [ shotgun, elli ] ]
			end },

		{ native_httpc,
			begin
			  trace_bridge:info_fmt( "Starting LEEC (httpc-based), with "
				  "following start options:~n  ~p.", [ StartOptions ] ),
			  web_utils:start( _Opt=ssl )
			end } ] ),

	JsonParserState = json_utils:start_parser(),

	{ ok, _AppNames } = application:ensure_all_started( leec ),

	% Usually none, already started by framework (ex: otp_utils):
	%trace_bridge:debug_fmt( "Applications started: ~p.", [ AppNames ] ),

	% Not registered in naming service on purpose, to allow for concurrent ACME
	% interactions (i.e. multiple, parallel instances).
	%
	% Calls init/1 on the new process, and returns its outcome:
	% (the FSM shall use any bridge as well)
	%
	gen_statem:start_link( ?MODULE,
		_InitParams={ StartOptions, JsonParserState, MaybeBridgeSpec },
		_Opts=[] ).



% @doc Returns the default options for certificate requests, here enabling the
% async (non-blocking) mode.
%
-spec get_default_cert_request_options() -> cert_req_option_map().
get_default_cert_request_options() ->
	get_default_cert_request_options( _Async=true ).


% @doc Returns the default optionsfor certificate requests, with specified async
% mode.
%
-spec get_default_cert_request_options( boolean() ) -> cert_req_option_map().
get_default_cert_request_options( Async ) when is_boolean( Async ) ->
	#{ async => Async,
	   netopts => #{ timeout => ?default_timeout,

					 % To avoid the following warning: 'Authenticity is not
					 % established by certificate path validation' (however, for
					 % unspecified reasons, apparently some instances thereof
					 % remain output).
					 %
					 % (verify_peer could be used instead, yet a specific,
					 % preferably ordered, list of the trusted DER-encoded
					 % certificates would then have to be specified, see
					 % https://erlang.org/doc/man/ssl.html#type-cert; here we
					 % loose the Man-in-the-Middle protection, but TLS still
					 % provides protection against "casual" eavesdroppers)
					 %
					 ssl => #{ verify => verify_none } } }.



% @doc Generates, once started, asynchronously (in a non-blocking manner), a new
% certificate for the specified domain (FQDN).
%
% Parameters:
%
% - Domain is the domain name to generate an ACME certificate for
%
% - FsmPid is the PID of the FSM to rely on
%
% Returns:
%
% - 'async' if async is set (the default being sync)
%
% - {error, Err} if a failure happens
%
% Belongs to the user-facing API; requires the LEEC service to be already
% started.
%
-spec obtain_certificate_for( domain(), fsm_pid() ) -> 'async' | error_term().
obtain_certificate_for( Domain, FsmPid ) ->
	obtain_certificate_for( Domain, FsmPid,
							get_default_cert_request_options() ).



% @doc Generates, once started, synchronously (in a blocking manner) or not, a
% new certificate for the specified domain (FQDN).
%
% Parameters:
%
% - Domain is the domain name to generate an ACME certificate for
%
% - FsmPid is the PID of the FSM to rely on
%
% - CertReqOptionMap is a map listing the options applying to this certificate
% request, whose key (as atom)/value pairs (all optional except 'async' and
% 'netopts') are:
%
%    - 'async' / boolean(): if true, blocks until complete and returns generated
%    certificate filename if false, immediately returns
%
%    - 'callback' / fun/1: function executed when Async is true, once domain
%    certificate has been successfully generated
%
%    - 'netopts' / map(): mostly to specify an HTTP timeout or SSL client
%    options
%
%    - 'challenge_type' / challenge_type() is the type of challenge to rely on
%    when interacting with the ACME server
%
%    - 'sans' / [ any_san() ]: a list of the Subject Alternative Names for that
%    certificate
%
% Returns:
%
% - if synchronous (the default): either {certificate_ready, BinFilePath} if
% successful, otherwise {error, Err}
%
% - otherwise (asynchronous), 'async'
%
% Belongs to the user-facing API; requires the LEEC service to be already
% started.
%
-spec obtain_certificate_for( Domain :: domain(), fsm_pid(),
							  cert_req_option_map() ) ->
		'async' | { 'certificate_ready', bin_file_path() } | error_term().
obtain_certificate_for( Domain, FsmPid, CertReqOptionMap )
  when is_pid( FsmPid ) andalso is_map( CertReqOptionMap ) ->

	% To ensure that all needed option entries are always defined:
	ReadyCertReqOptMap = maps:merge( _Def=get_default_cert_request_options(),
									 _Prioritary=CertReqOptionMap ),

	% Also a check:
	case ReadyCertReqOptMap of

		#{ async := true } ->

			% Still being in user process, bridge applies:
			cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
			  "Requesting FSM ~w to generate asynchronously a certificate "
			  "for domain '~ts'.", [ FsmPid, Domain ] ) ),

			% Asynchronous then, in a separate process from the user one, yet
			% using the same bridge as set for this caller process:
			%
			_Pid = ?myriad_spawn_link( ?MODULE, obtain_cert_helper,
				[ Domain, FsmPid, ReadyCertReqOptMap,
				  trace_bridge:get_bridge_info() ] ),
			async;

		#{ async := false } ->
			% Everything done in user process then, whose bridge (if any) shall
			% be already set:
			%
			cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
			  "Requesting FSM ~w to generate synchronously a certificate "
			  "for domain '~ts'.", [ FsmPid, Domain ] ) ),

			% Thus a direct synchronous return:
			obtain_cert_helper( Domain, FsmPid, ReadyCertReqOptMap )

	end;

obtain_certificate_for( _Domain, FsmPid, CertReqOptionMap )
  when is_pid( FsmPid ) ->
	throw( { not_an_option_map, CertReqOptionMap } );

obtain_certificate_for( _Domain, FsmPid, _CertReqOptionMap ) ->
	throw( { not_pid, FsmPid } ).




% @doc Spawn helper, to be called either from a dedicated process or not,
% depending on being async or not.
%
% @hidden
%
-spec obtain_cert_helper( Domain :: domain(), fsm_pid(),
						  cert_req_option_map() ) ->
		{ 'certificate_ready', bin_file_path() } | error_term().
obtain_cert_helper( Domain, FsmPid,
					CertReqOptionMap=#{ async := Async,
										netopts := NetOpts } ) ->

	Timeout = maps:get( timeout, NetOpts, ?default_timeout ),

	BinDomain = text_utils:ensure_binary( Domain ),

	ServerRef = FsmPid,

	% Expected to be in the 'idle' state, hence to trigger idle({create,
	% BinDomain, Opts}, _, LEState):
	%
	CreationRes = case gen_statem:call( ServerRef,
			_Request={ create, BinDomain, CertReqOptionMap }, Timeout ) of

		% State of FSM shall thus be 'idle' now:
		ErrorTerm={ creation_failed, Error } ->
			trace_bridge:error_fmt( "Creation error reported by FSM ~w: ~p.",
									[ FsmPid, Error ] ),
			{ error, ErrorTerm };

		% State of FSM shall thus be 'pending' now; should then transition after
		% some delay to 'valid'; we wait for it:
		%
		creation_pending ->

			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				"FSM ~w reported that creation is pending, "
				"waiting for the validation of challenge(s).", [ FsmPid ] ) ),

			case wait_challenges_valid( FsmPid ) of

				ok ->
					% So here the FSM is expected to have switched from
					% 'pending' to 'valid'. Then:

					% Most probably 'valid':
					_LastReadStatus = gen_statem:call( ServerRef,
											_Req=switchTofinalize, Timeout ),

					case wait_creation_completed( FsmPid, _Count=20 ) of

						Reply={ certificate_ready, BinCertFilePath } ->
							cond_utils:if_defined( leec_debug_fsm,
								trace_bridge:debug_fmt( "Domain '~ts' "
									"finalized for ~w, returning certificate "
									"path '~ts'.",
									[ Domain, FsmPid, BinCertFilePath ] ) ),
							Reply;

						Error ->
							trace_bridge:error_fmt( "Error for FSM ~w when "
								"finalizing domain '~ts': ~p.",
								[ FsmPid, Domain, Error ] ),
							Error

					end;

				% Typically {error, timeout}:
				OtherError ->
					cond_utils:if_defined( leec_debug_fsm,
						trace_bridge:debug_fmt( "Reset of FSM ~w for '~ts' "
						  "after error ~p.", [ FsmPid, Domain, OtherError ] ) ),
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
			Callback = maps:get( callback, CertReqOptionMap,
				_DefaultCallback=fun( Ret ) ->
					trace_bridge:warning_fmt( "Default async callback called "
						"for ~w regarding result ~p.", [ FsmPid, Ret ] )
								 end ),

			trace_bridge:debug_fmt( "Async callback called "
				"for ~w regarding result ~p.", [ FsmPid, CreationRes ] ),

			Callback( CreationRes );

		_ ->
			ok

	end,

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"Return for domain '~ts' creation (FSM: ~w): ~p",
		[ Domain, FsmPid, CreationRes ] ) ),

	CreationRes.



% @doc Spawn, bridged helper, to be called either from a dedicated process or
% not, depending on being async or not.
%
% @hidden
%
-spec obtain_cert_helper( Domain :: domain(), fsm_pid(), cert_req_option_map(),
						  maybe( trace_bridge:bridge_info() ) ) ->
		{ 'certificate_ready', bin_file_path() } | error_term().
obtain_cert_helper( Domain, FsmPid, CertReqOptionMap, MaybeBridgeInfo ) ->

	% Let's inherit the creator bridge first:
	trace_bridge:set_bridge_info( MaybeBridgeInfo ),

	% And then branch to the main logic:
	obtain_cert_helper( Domain, FsmPid, CertReqOptionMap ).



% @doc Stops the specified instance of LEEC service.
-spec stop( fsm_pid() ) -> void().
stop( FsmPid ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"Requesting FSM ~w to stop.", [ FsmPid ] ) ),

	% No more gen_fsm:sync_send_all_state_event/2 available, so
	% handle_call_for_all_states/4 will have to be called from all states
	% defined:
	%
	% (synchronous)
	%
	Res = gen_statem:call( _ServerRef=FsmPid, _Request=stop, ?base_timeout ),

	% Not stopped here, as stopping is only going back to the 'idle' state:
	%json_utils:stop_parser().

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"FSM ~w stopped (result: ~p).", [ FsmPid, Res ] ) ).





% FSM internal API.


% @doc Initializes the LEEC state machine.
%
% Parameters:
%
% - init TLS private key and its JWS
%
% - fetch ACME directory
%
% - get valid nonce
%
% Will make use of any trace bridge transmitted.
%
% Transitions to the 'idle' initial state.
%
-spec init( { [ start_option() ], json_utils:parser_state(),
				maybe( trace_bridge:bridge_spec() ) } ) ->
		{ 'ok', InitialStateName :: 'idle', InitialData :: le_state() }.
init( { StartOptions, JsonParserState, MaybeBridgeSpec } ) ->

	% First action is to register this (unregistered by design) FSM to any
	% specified trace bridge:
	%
	trace_bridge:register( MaybeBridgeSpec ),

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"Initialising, with following options:~n  ~p.", [ StartOptions ] ) ),

	InitLEState = #le_state{ json_parser_state=JsonParserState,
							 tcp_connection_cache=table:new() },

	LEState = setup_mode( get_start_options( StartOptions, InitLEState ) ),

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Initial state:~n  ~p", [ self(), LEState ] ) ),

	BinCertDirPath = LEState#le_state.cert_dir_path,

	% Creates the private key (a tls_private_tls_public_key()) of this LEEC
	% agent, and initialises its JWS; in case of parallel creations, ensuring
	% automatically the uniqueness of its filename is not trivial:
	%
	KeyFileInfo = case LEState#le_state.agent_key_file_info of

		% If a key is to be created:
		undefined ->
			% We prefer here devising out own agent filename, lest its automatic
			% uniqueness is difficult to obtain (which is the case); we may use
			% in the future any user-specified identifier (see user_id field);
			% for now we stick to a simple approach based on the PID of this
			% LEEC FSM (no domain known yet):
			%
			%UniqFilename = text_utils:format(
			%  "leec-agent-private-~ts.key",
			%  [ LEState#le_state.user_id ] ),

			% A prior run might have left a file with the same name, it will be
			% overwritten (with a warning) in this case:
			%
			UniqFilename = text_utils:bin_format( "leec-agent-private-~ts.key",
								[ text_utils:pid_to_core_string( self() ) ] ),

			% Already a binary:
			{ new, UniqFilename };


		% If a key is to be reused (absolute path, or relative to
		% BinCertDirPath):
		%
		CurrentKeyBinPath ->
			CurrentKeyBinPath

	end,

	AgentPrivateKey = leec_tls:obtain_private_key( KeyFileInfo,
												   BinCertDirPath ),

	KeyJws = leec_jws:init( AgentPrivateKey ),

	OptionMap = LEState#le_state.cert_req_option_map,

	% Directory map is akin to:
	%
	% #{<<"3TblEIQUCPk">> =>
	%	  <<"ACME_COMM/t/adding-random-entries-to-the-directory/31417">>,
	%   <<"keyChange">> =>
	%	  <<"ACME_BASE/acme/key-change">>,
	%   <<"meta">> =>
	%	  #{<<"caaIdentities">> => [<<"letsencrypt.org">>],
	%		<<"termsOfService">> =>
	%	<<"https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf">>,
	%		<<"website">> =>
	%			<<"https://letsencrypt.org/docs/staging-environment/">>},
	%   <<"newAccount">> =>
	%	  <<"ACME_BASE/acme/new-acct">>,
	%   <<"newNonce">> =>
	%	  <<"ACME_BASE/acme/new-nonce">>,
	%   <<"newOrder">> =>
	%	  <<"ACME_BASE/acme/new-order">>,
	%   <<"revokeCert">> =>
	%	  <<"ACME_BASE/acme/revoke-cert">>}

	{ URLDirectoryMap, DirLEState } = leec_api:get_directory_map(
		LEState#le_state.env, OptionMap, LEState ),

	{ FirstNonce, NonceLEState } =
		leec_api:get_nonce( URLDirectoryMap, OptionMap, DirLEState ),

	cond_utils:if_defined( leec_debug_fsm,
		trace_bridge:debug_fmt( "[~w][state] Switching initially to 'idle'.",
								[ self() ] ) ),

	% Next transition typically triggered by user code calling
	% obtain_certificate_for/{2,3}:
	%
	{ ok, _NewStateName=idle,
	  NonceLEState#le_state{ directory_map=URLDirectoryMap,
							 agent_private_key=AgentPrivateKey,
							 jws=KeyJws,
							 nonce=FirstNonce } }.



% @doc Tells about the retained mode regarding callback. Here, one callback
% function per state, akin to gen_fsm.
%
-spec callback_mode() -> gen_statem:callback_mode().
callback_mode() ->
	% state_enter useful to trigger code once, when entering the 'finalize'
	% state for the first time:
	%
	[ state_functions, state_enter ].



% @doc Returns the (absolute, binary) path of the current private key of the
% LEEC agent.
%
% Useful so that the same key can be used for multiple ACME orders (possibly in
% parallel) rather than multiplying the keys.
%
% (exported API helper)
%
-spec get_agent_key_path( fsm_pid() ) -> 'error' | maybe( bin_file_path() ).
get_agent_key_path( FsmPid ) ->

	case catch gen_statem:call( _ServerRef=FsmPid,
								_Request=get_agent_key_path ) of

		% Process not started, wrong state, etc.:
		{ 'EXIT', ExitReason } ->
			trace_bridge:error_fmt( "Agent key path not obtained: ~p.",
									[ ExitReason ] ),
			error;

		BinKeyPath ->
			BinKeyPath

	end.



% @doc Returns the ongoing challenges with pre-computed thumbprints.
%
% Returns #{Challenge => Thumbrint} if ok, 'error' if fails.
%
% (exported API helper)
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



% @doc Sends the ongoing challenges to the specified process.
%
% Typically useful in a slave operation mode, when the web handler cannot access
% directly the PID of the LEEC FSM: this code is then called by a third-party
% process (ex: a certificate manager one, statically known of the web handler,
% and triggered by it), and returns the requested challenged to the specified
% target PID (most probably the one of the web handler itself).
%
% (exported API helper)
%
-spec send_ongoing_challenges( fsm_pid(), pid() ) -> void().
send_ongoing_challenges( FsmPid, TargetPid ) ->

	% No error possibly reported:
	gen_statem:cast( _ServerRef=FsmPid,
					 _Msg={ send_ongoing_challenges, TargetPid } ).




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



% @doc Manages the 'idle' state, the initial state, typically used when awaiting
% for certificate requests to be triggered.
%
% idle(get_ongoing_challenges | send_ongoing_challenges): nothing done
%
-spec idle( event_type(), event_content(), le_state() ) ->
				state_callback_result().
% idle with request {create, BinDomain, CertReqOptionMap}: starts the
% certificate creation procedure.
%
% Starts a new certificate creation process:
%  - create a new ACME account, or connect to a pre-existing one
%  - send a new order
%  - request authorization (returns challenges list)
%  - initiate chosen challenge
%
% Transition to:
%  - 'idle' if process failed
%  - 'pending' waiting for challenges to be complete
%
idle( _EventType=enter, _PreviousState, _Data ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Entering the 'idle' state.", [ self() ] ) ),

	keep_state_and_data;


idle( _EventType={ call, From },
	  _EventContentMsg=_Request={ create, BinDomain, CertReqOptionMap },
	  _Data=LEState=#le_state{ directory_map=DirMap, agent_private_key=PrivKey,
							   jws=Jws, nonce=Nonce } ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] While idle: received a certificate creation "
		"request for domain '~ts', with following options:~n  ~p.",
		[ self(), BinDomain, CertReqOptionMap ] ) ),

	% Ex: 'http-01', 'tls-sni-01', etc.:
	ChallengeType = maps:get( challenge_type, CertReqOptionMap,
							  _DefaultChlgType='http-01' ),

	case ChallengeType of

		'http-01' ->
			ok;

		OtherChallengeType ->
			throw( { unsupported_challenge_type, OtherChallengeType } )

	end,

	{ { AccountDecodedJsonMap, AccountLocationUri, AccountNonce },
	  CreateLEState } = leec_api:get_acme_account( DirMap, PrivKey,
							Jws#jws{ nonce=Nonce }, CertReqOptionMap, LEState ),

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
	% "ACME_BASE/acme/acct/16210968"

	case maps:get( <<"status">>, AccountDecodedJsonMap ) of

		<<"valid">> ->
			ok;

		AccountUnexpectedStatus ->
			throw( { unexpected_status, AccountUnexpectedStatus,
					 account_creation } )

	end,

	AccountKeyAsMap = maps:get( <<"key">>, AccountDecodedJsonMap ),

	AccountKey = leec_tls:map_to_key( AccountKeyAsMap ),

	cond_utils:if_defined( leec_debug_keys, trace_bridge:debug_fmt(
		"[~w] The obtained ACME account key is:~n  ~p",
		[ self(), AccountKey ] ) ),

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] ACME account key obtained.", [ self() ] ) ),

	% Apparently a different JWS then:
	AccountJws = #jws{ alg=Jws#jws.alg, kid=AccountLocationUri,
					   nonce=AccountNonce },

	% Subject Alternative Names:
	Sans = maps:get( sans, CertReqOptionMap, _DefaultSans=[] ),

	BinSans = [ text_utils:ensure_binary( S ) || S <- Sans ],

	BinDomains = [ BinDomain | BinSans ],

	% Will transition to 'pending' to manage this request:
	{ { OrderDecodedJsonMap, OrderLocationUri, OrderNonce }, ReqState } =
		leec_api:request_new_certificate( DirMap, BinDomains, PrivKey,
								AccountJws, CertReqOptionMap, CreateLEState ),

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

	AuthLEState = ReqState#le_state{ domain=BinDomain, jws=AccountJws,
		account_key=AccountKey, nonce=OrderNonce, sans=BinSans },

	AuthUris = maps:get( <<"authorizations">>, OrderDecodedJsonMap ),

	{ AuthPair, PerfLEState } = perform_authorization( ChallengeType, AuthUris,
													   AuthLEState ),

	{ NewStateName, Reply, NewUriChallengeMap, FinalNonce } =
			case AuthPair of

		{ UriChallengeMap, AuthNonce } ->
			{ pending, creation_pending, UriChallengeMap, AuthNonce };

		% Currently never happens:
		{ error, Err, ErrAuthNonce } ->
			{ idle, { creation_failed, Err }, _ResetChlgMap=#{}, ErrAuthNonce }

	end,

	FinalLEState = PerfLEState#le_state{ nonce=FinalNonce, order=LocOrder,
										 challenges=NewUriChallengeMap },

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w][state] Switching from 'idle' to '~ts'.",
		[ self(), NewStateName ] ) ),

	{ next_state, NewStateName, _NewData=FinalLEState,
	  _Action={ reply, From, Reply } };


idle( _EventType={ call, FromPid },
	  _EventContentMsg=_Request=get_ongoing_challenges, _Data=_LEState ) ->

	trace_bridge:warning_fmt( "Received a get_ongoing_challenges request call "
		"from ~w while being idle.", [ FromPid ] ),

	% Clearer than {next_state, idle, LEState, {reply, FromPid,
	% _Reply=no_challenge}}:
	%
	{ keep_state_and_data, { reply, FromPid, _Reply=no_challenge } };


idle( _EventType=cast,
	  _EventContentMsg=_Request={ send_ongoing_challenges, TargetPid },
	  _Data=_LEState ) ->

	trace_bridge:warning_fmt( "Ignored a send_ongoing_challenges cast "
		"(targeting ~w) while being idle.", [ TargetPid ] ),

	keep_state_and_data;


% Possibly Request=stop:
idle( _EventType={ call, ServerRef }, _EventContentMsg=Request,
	  _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=idle, LEState );

idle( EventType, EventContentMsg, _LEState ) ->
	throw( { unexpected_event, EventType, EventContentMsg, { state, idle } } ).




% @doc Manages the 'pending' state, when challenges are on-the-go, that is being
% processed with the ACME server.
%
pending( _EventType=enter, _PreviousState, _Data ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Entering the 'pending' state.", [ self() ] ) ),

	keep_state_and_data;


% Returns a list of the currently ongoing challenges, with pre-computed
% thumbprints, i.e. a thumbprint_map().
%
pending( _EventType={ call, From }, _EventContentMsg=get_ongoing_challenges,
		 _Data=LEState=#le_state{ account_key=AccountKey,
								  challenges=TypeChallengeMap } ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Getting ongoing challenges.", [ self() ] ) ),

	% get_key_authorization/3 not returning a le_state():
	ThumbprintMap = maps:from_list( [ { Token,
		_Thumbprint=leec_jws:get_key_authorization( AccountKey, Token,
													LEState ) }
		  || #{ <<"token">> := Token } <- maps:values( TypeChallengeMap ) ] ),

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Returning (get) from pending state challenge "
		"thumbprint map ~p.", [ self(), ThumbprintMap ] ) ),

	{ next_state, _SameState=pending, LEState,
	  _Action={ reply, From, _RetValue=ThumbprintMap } };


% Same as previous, except that the returned lessage is sent to target PID
% rather than to caller.
%
pending( _EventType=cast,
		 _EventContentMsg={ send_ongoing_challenges, TargetPid },
		 _Data=LEState=#le_state{ account_key=AccountKey,
								  challenges=TypeChallengeMap } ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Ongoing challenges to be sent to ~w.", [ self(), TargetPid ] ) ),

	% get_key_authorization/3 not returning a le_state():
	ThumbprintMap = maps:from_list( [ { Token,
		_Thumbprint=leec_jws:get_key_authorization( AccountKey, Token,
													LEState ) }
		  || #{ <<"token">> := Token } <- maps:values( TypeChallengeMap ) ] ),

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Returning (send) from pending state challenge "
		"thumbprint map ~p.", [ self(), ThumbprintMap ] ) ),

	TargetPid ! { leec_result, ThumbprintMap },

	keep_state_and_data;


% Checks if all challenges are completed, and returns the (possibly new) current
% state.
%
% Switches to the 'valid' state iff all challenges are validated.
%
% Transitions to:
%   - 'pending' if at least one challenge is not completed yet
%   - 'valid' if all challenges are complete
%
pending( _EventType={ call, From }, _EventContentMsg=check_challenges_completed,
		 _Data=LEState=#le_state{
					order=#{ <<"authorizations">> := AuthorizationsUris },
					nonce=InitialNonce, agent_private_key=PrivKey, jws=Jws,
					cert_req_option_map=CertReqOptionMap } ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Checking whether challenges are completed.", [ self() ] ) ),

	% Checking the status for each authorization URI (one per host/SAN):
	{ NextStateName, ResultingNonce, FoldLEState } = lists:foldl(

		fun( AuthUri, _Acc={ AccStateName, AccNonce, AccState } ) ->

			{ { AuthJsonMap, _Location, NewNonce }, ReqState } =
					leec_api:request_authorization( AuthUri, PrivKey,
						Jws#jws{ nonce=AccNonce }, CertReqOptionMap, AccState ),

			BinStatus = maps:get( <<"status">>, AuthJsonMap ),

			cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
				"[~w] For auth URI ~ts, received status '~ts'.",
				[ self(), AuthUri, BinStatus ] ) ),

			% State remains 'pending' until all URIs report 'valid':
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
					trace_bridge:warning_fmt( "[~w] For auth URI ~ts, "
						"switching from '~ts' to unsupported 'deactivated' "
						"state.", [ self(), AuthUri, AnyState ] ),
					deactivated;

				{ AnyState, <<"expired">> } ->
					trace_bridge:warning_fmt( "[~w] For auth URI ~ts, "
						"switching from '~ts' to unsupported 'expired' "
						"state.", [ self(), AuthUri, AnyState ] ),
					expired;

				{ AnyState, <<"revoked">> } ->
					trace_bridge:warning_fmt( "[~w] For auth URI ~ts, "
						"switching from '~ts' to unsupported 'revoked' state.",
						[ self(), AuthUri, AnyState ] ),
					revoked;

				% Typically from 'valid', after the ACME time-outs short of
				% being able to getch relevant challenges from local webserver:
				%
				{ _AnyState, <<"invalid">> } ->
					invalid;

				% By default remains in the current state (including 'pending'):
				{ AccStateName, AnyBinStatus } ->
					trace_bridge:debug_fmt( "[~w] For auth URI ~ts, staying "
						"in '~ts' despite having received status '~p'.",
						[ self(), AuthUri, AccStateName, AnyBinStatus ] ),
					AccStateName;

				{ AnyOtherState, UnexpectedBinStatus } ->

					trace_bridge:error_fmt( "[~w] For auth URI ~ts, "
						"while in '~ts' state, received unexpected "
						"status '~p'.",
						[ self(), AuthUri, AnyOtherState,
						  UnexpectedBinStatus ] ),

					throw( { unexpected_auth_status, UnexpectedBinStatus,
							 self(), AnyOtherState, AuthUri } )

			end,

			{ NewStateName, NewNonce, ReqState }

		end,
		_Acc0={ _InitialNextStateName=valid, InitialNonce, LEState },
		_List=AuthorizationsUris ),


	% Be nice to ACME server:
	case NextStateName of

		pending ->
			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				"[~w] Remaining in 'pending' state.", [ self() ] ) ),
			timer:sleep( 1000 );

		_ ->
			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
			  "[~w] Check resulted in switching from 'pending' to '~ts' state.",
			  [ self(), NextStateName ] ), ok )

	end,

	{ next_state, NextStateName,
	  _NewData=FoldLEState#le_state{ nonce=ResultingNonce },
	  _Action={ reply, From, _RetValue=NextStateName } };


pending( _EventType={ call, From }, _EventContentMsg=Request=switchTofinalize,
		 _Data=_LEState ) ->

	%cond_utils:if_defined( leec_debug_exchanges,
	trace_bridge:debug_fmt( "[~w] Received, while in 'pending' state, "
							"request '~ts' from ~w, currently ignored.",
							[ self(), Request, From ] ),

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



% @doc Manages the 'valid' state.
%
% When challenges have been successfully completed, finalizes the ACME order and
% generates TLS certificate.
%
% Returns Status, the order status.
%
% Transitions to 'finalize' state.
%
valid( _EventType=enter, _PreviousState, _Data ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Entering the 'valid' state.", [ self() ] ) ),

	keep_state_and_data;

valid( _EventType={ call, _ServerRef=From },
	   _EventContentMsg=_Request=switchTofinalize,
	   _Data=LEState=#le_state{ mode=Mode, domain=BinDomain, sans=SANs,
			cert_dir_path=BinCertDirPath, order=OrderDirMap,
			agent_private_key=PrivKey, jws=Jws, nonce=Nonce,
			cert_req_option_map=CertReqOptionMap } ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Trying to switch to finalize while being in the 'valid' state.",
		[ self() ] ) ),

	DestroyLEState = challenge_destroy( Mode, LEState ),

	KeyFilename = text_utils:binary_to_string( BinDomain ) ++ ".key",

	% To avoid a warning:
	file_utils:remove_file_if_existing(
	  file_utils:join( BinCertDirPath, KeyFilename ) ),

	% KeyFilePath is required for CSR generation:
	CreatedTLSPrivKey = leec_tls:obtain_private_key( { new, KeyFilename },
													 BinCertDirPath ),

	Csr = leec_tls:get_cert_request( BinDomain, BinCertDirPath, SANs ),

	{ { FinOrderDirMap, _BinLocUri, FinNonce }, FinLEState } =
		leec_api:finalize_order( OrderDirMap, Csr, PrivKey,
			Jws#jws{ nonce=Nonce }, CertReqOptionMap, DestroyLEState ),

	BinStatus = maps:get( <<"status">>, FinOrderDirMap ),

	% Expected to be 'finalize' sooner or later:
	ReadStateName = leec_api:binary_to_status( BinStatus ),

	% Update location in finalized order:
	LocOrderDirMap = FinOrderDirMap#{
				<<"location">> => maps:get( <<"location">>, OrderDirMap ) },

	LastLEState = FinLEState#le_state{ order=LocOrderDirMap,
		cert_key_file=CreatedTLSPrivKey#tls_private_key.file_path,
		nonce=FinNonce },

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w][state] Switching from 'valid' to 'finalize' "
		"(after having read '~ts').", [ self(), ReadStateName ] ) ),

	{ next_state, _NewStateName=finalize, _NewData=LastLEState,
	  _Action={ reply, From, _Reply=ReadStateName } };


valid( _EventType={ call, ServerRef }, _EventContentMsg=Request,
	   _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=valid,
								LEState );

valid( EventType, EventContentMsg, _LEState ) ->
	throw( { unexpected_event, EventType, EventContentMsg,
			 { state, valid }, self() } ).



% @doc Manages the 'finalize' state.
%
% When order is being finalized, and certificate generation is ongoing.
%
% Waits for certificate generation being complete (order status becoming
% 'valid').
%
% Returns the order status.
%
% Transitions to:
%   state 'processing': still ongoing
%   state 'valid'     : certificate is ready
%
finalize( _EventType=enter, _PreviousState, _Data ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Entering the 'finalize' state.", [ self() ] ) ),

	keep_state_and_data;

finalize( _EventType={ call, _ServerRef=From },
		  _EventContentMsg=_Request=manageCreation,
		  _Data=LEState=#le_state{ order=OrderMap, domain=BinDomain,
			  %agent_key_file_path=KeyFilePath,
			  cert_dir_path=BinCertDirPath,
			  agent_private_key=PrivKey, jws=Jws, nonce=Nonce,
			  cert_req_option_map=CertReqOptionMap } ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Getting progress of creation procedure "
		"based on order map:~n   ~p.", [ self(), OrderMap ] ) ),

	%trace_bridge:debug_fmt( "[~w] Getting progress of creation procedure "
	%						"based on order map.", [ self() ] ),

	Loc = maps:get( <<"location">>, OrderMap ),

	{ { NewOrderMap, _NullLoc, OrderNonce }, OrderState } =
		leec_api:get_order( Loc, PrivKey, Jws#jws{ nonce=Nonce },
							CertReqOptionMap, LEState ),

	BinStatus = maps:get( <<"status">>, NewOrderMap ),

	ReadStatus = leec_api:binary_to_status( BinStatus ),

	{ { Reply, NewStateName, NewNonce, NewJws }, ReadLEState } =
			case ReadStatus of

		processing ->

			cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
				"[~w] Certificate creation still in progress on server.",
				[ self() ] ) ),

			{ { creation_in_progress, finalize, OrderNonce, Jws }, OrderState };

		% Downloads certificate and saves it into file.
		%
		% Transitions to state 'idle': fsm complete, going back to initial
		% state.
		%
		valid ->

			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				"[~w] Finalizing certificate creation now.", [ self() ] ) ),

			%BinKeyFilePath = text_utils:string_to_binary( KeyFilePath ),

			% Downloads certificate:

			{ { BinCert, DownloadNonce }, CertLEState } =
				leec_api:get_certificate( OrderMap, PrivKey,
					Jws#jws{ nonce=OrderNonce }, CertReqOptionMap, OrderState ),

			Domain = text_utils:binary_to_string( BinDomain ),

			CertFilePath =
				leec_tls:write_certificate( Domain, BinCert, BinCertDirPath ),

			BinCertFilePath = text_utils:string_to_binary( CertFilePath ),

			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				"[~w] Certificate generated in ~ts, "
				"switching from 'finalize' to the 'idle' state.",
				[ self(), BinCertFilePath ] ) ),

			% Shall we continue with the same account for any next operation?
			% No, and the current JWS would not be suitable for that (ex: not
			% having the public key of that LEEC agent), and anyway we prefer
			% creating a new account each time a new operation is performed (as
			% ~90 days may elapse between two operations). So:
			%
			AgentKeyJws = leec_jws:init( PrivKey ),

			% Safer, not wasting idle connections, bound to fail after some time
			% anyway:
			%
			leec_api:close_tcp_connections(
			  OrderState#le_state.tcp_connection_cache ),

			CloseLEState = CertLEState#le_state{
							tcp_connection_cache=table:new() },

			{ { { certificate_ready, BinCertFilePath }, idle, DownloadNonce,
				AgentKeyJws }, CloseLEState };


		% Like for 'processing', yet with a different trace:
		OtherStatus ->
			trace_bridge:warning_fmt( "[~w] Unexpected read status while "
				"finalizing: '~ts' (ignored).", [ self(), OtherStatus ] ),
			{ { creation_in_progress, finalize, OrderNonce, Jws }, OrderState }

	end,

	FinalLEState = ReadLEState#le_state{ order=NewOrderMap, jws=NewJws,
										 nonce=NewNonce },

	{ next_state, NewStateName, _NewData=FinalLEState,
	  _Action={ reply, From, Reply } };


finalize( _EventType={ call, ServerRef }, _EventContentMsg=Request,
		  _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=finalize,
								LEState );


finalize( UnexpectedEventType, EventContentMsg, _LEState ) ->

	trace_bridge:error_fmt( "Unknown event ~p (content: ~p) in "
		"finalize status.", [ UnexpectedEventType, EventContentMsg ] ),

	%{ reply, { error, UnexpectedEventType }, finalize, LEState }.

	throw( { unexpected_event, UnexpectedEventType, EventContentMsg,
			 { state, finalize } } ).



% @doc Manages the 'invalid' state.
%
% When order is being finalized, and certificate generation is ongoing.
%
% Waits for certificate generation being complete (order status == 'valid').
%
% Returns the order status.
%
% Transitions to:
%   state 'processing': still ongoing
%   state 'valid'     : certificate is ready
%
invalid( _EventType=enter, _PreviousState, _Data=LEState ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Entering the 'invalid' state.", [ self() ] ) ),

	trace_bridge:error_fmt( "[~w] Reached the (stable) 'invalid' state for "
		"domain '~ts'.", [ self(), LEState#le_state.domain ] ),

	keep_state_and_data.




% Callback section.


% @doc Handles the specified call in the same way for all states.
%
% (helper)
%
-spec handle_call_for_all_states( server_ref(), request(), state_name(),
								  le_state() ) -> state_callback_result().
handle_call_for_all_states( ServerRef, _Request=get_status, StateName,
							_LEState ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Returning current status: '~ts'.", [ ServerRef, StateName ] ) ),

	Res = StateName,

	{ keep_state_and_data, _Actions={ reply, _From=ServerRef, Res } };


handle_call_for_all_states( ServerRef, _Request=get_agent_key_path, StateName,
							LEState ) ->

	MaybeKeyPath = case LEState#le_state.agent_private_key of

		undefined ->
			undefined;

		PrivKey ->
			PrivKey#tls_private_key.file_path

	end,

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Returning agent key path (while in state '~ts'): ~p.",
		[ ServerRef, StateName, MaybeKeyPath ] ) ),

	{ keep_state_and_data, _Actions={ reply, _From=ServerRef,
									  _Res=MaybeKeyPath } };


handle_call_for_all_states( ServerRef, _Request=stop, StateName,
							LEState=#le_state{ mode=Mode } ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Received a stop request from ~ts state.",
		[ ServerRef, StateName ] ) ),

	DestroyLEState = challenge_destroy( Mode, LEState ),

	% Stopping is just returning back to idle (no action):

	%{ stop_and_reply, _Reason, _Reply={ reply, ServerRef, ok },
	%   _Data=LEState }.

	{ next_state, _NextState=idle, _NewData=DestroyLEState };


handle_call_for_all_states( ServerRef, Request, StateName, _LEState ) ->

	trace_bridge:error_fmt( "[~w] Received an unexpected request, ~p, "
		"while in state ~p.", [ ServerRef, Request, StateName ] ),

	throw( { unexpected_request, Request, ServerRef, StateName } ).



% Standard callbacks:

% @doc Standard termination callback.
terminate( _, _, _ ) ->
	ok.


% @doc Standard "code change" callback.
code_change( _, StateName, LEState, _ ) ->
	{ ok, StateName, LEState }.




% Helpers.


% @doc Parses the start/1 options.
%
% Available options are:
%
% - staging: runs in staging environment (otherwise running in production one)
%
% - mode: webroot, slave or standalone
%
% - agent_key_file_path: to reuse an existing agent TLS key
%
% - cert_dir_path: path to read/save TLS certificates, keys and CSR requests
%
% - webroot_dir_path: the webroot directory, in a conventional subdirectory of
% which challenge answers shall be written so that the ACME server can download
% them
%
% - port: the TCP port at which the corresponding webserver shall be available,
% in standalone mode
%
% - http_timeout: timeout for ACME API requests (in milliseconds)
%
% Returns LEState (type record 'le_state') filled with corresponding, checked
% option values.
%
-spec get_start_options( [ start_option() ], le_state() ) -> le_state().
get_start_options( _Opts=[], LEState ) ->
	LEState;

get_start_options( _Opts=[ staging | T ], LEState ) ->
	get_start_options( T, LEState#le_state{ env=staging } );

get_start_options( _Opts=[ { mode, Mode } | T ], LEState ) ->
	case lists:member( Mode, [ webroot, slave, standalone ] ) of

		true ->
			ok;

		false ->
			throw( { invalid_leec_mode, Mode } )

	end,
	get_start_options( T, LEState#le_state{ mode=Mode } );

% To re-use a previously-stored agent private key:
get_start_options( _Opts=[ { agent_key_file_path, KeyFilePath } | T ],
				   LEState ) ->

	AgentKeyFilePath = text_utils:ensure_string( KeyFilePath ),

	% Not knowin the certificate directory yet, so checking only if absolute:
	case file_utils:is_absolute_path( AgentKeyFilePath ) of

		true ->
			case file_utils:is_existing_file_or_link( AgentKeyFilePath ) of

				true ->
					case file_utils:is_user_readable( AgentKeyFilePath ) of

						true ->
							BinAgentKeyFilePath = text_utils:string_to_binary(
									AgentKeyFilePath ),

							get_start_options( T, LEState#le_state{
								agent_key_file_info=BinAgentKeyFilePath } );

						false ->
							throw( { agent_key_file_not_user_readable,
									 AgentKeyFilePath,
									 system_utils:get_user_name_safe() } )

					end;

				false ->
					throw( { non_existing_agent_key_file, AgentKeyFilePath } )

			end;

		false ->
			% No possible check yet:
			get_start_options( T,
				LEState#le_state{ agent_key_file_info=
					text_utils:string_to_binary( AgentKeyFilePath ) } )

	end;


get_start_options( _Opts=[ { cert_dir_path, BinCertDirPath } | T ], LEState )
  when is_binary( BinCertDirPath ) ->
	case file_utils:is_existing_directory_or_link( BinCertDirPath ) of

		true ->
			get_start_options( T, LEState#le_state{
									cert_dir_path=BinCertDirPath } );

		false ->
			throw( { non_existing_certificate_directory,
					 text_utils:binary_to_string( BinCertDirPath ) } )

	end;

get_start_options( _Opts=[ { cert_dir_path, CertDirPath } | T ], LEState ) ->
	BinCertDirPath = text_utils:string_to_binary( CertDirPath ),
	get_start_options( [ { cert_dir_path, BinCertDirPath } | T ], LEState );


get_start_options( _Opts=[ { webroot_dir_path, BinWebDirPath } | T ], LEState )
  when is_binary( BinWebDirPath ) ->
	case file_utils:is_existing_directory_or_link( BinWebDirPath ) of

		true ->
			get_start_options( T,
						 LEState#le_state{ webroot_dir_path=BinWebDirPath } );

		false ->
			throw( { non_existing_webroot_directory,
					 text_utils:binary_to_string( BinWebDirPath ) } )

	end;

get_start_options( _Opts=[ { webroot_dir_path, WebDirPath } | T ], LEState ) ->
	BinWebDirPath = text_utils:ensure_binary( WebDirPath ),
	get_start_options( [ { webroot_dir_path, BinWebDirPath } | T ], LEState );


get_start_options( _Opts=[ { port, Port } | T ], LEState )
  when is_integer( Port ) ->
	get_start_options( T, LEState#le_state{ port=Port } );

get_start_options( _Opts=[ { port, Port } | _T ], _LEState ) ->
	throw( { invalid_standalone_tcp_port, Port } );

get_start_options( _Opts=[ { http_timeout, Timeout } | T ], LEState )
  when is_integer( Timeout ) ->
	get_start_options( T, LEState#le_state{
			  cert_req_option_map=#{ netopts => #{ timeout => Timeout } } } );

get_start_options( _Opts=[ { http_timeout, Timeout } | _T ], _LEState ) ->
	throw( { invalid_http_timeout, Timeout } );

get_start_options( _Opts=[ Unexpected | _T ], _LEState ) ->
	trace_bridge:error_fmt( "Invalid LEEC option specified: ~p.",
							[ Unexpected ] ),
	throw( { invalid_leec_option, Unexpected } ).



% @doc Setups the context of chosen mode.
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



% @doc Loops a few times on authorization check until challenges are all
% validated (with increasing waiting times after each attempt); if successful,
% the FSM should be in 'valid' state when returning.
%
% Returns:
%
% - {error, timeout} if failed after X loops
%
% - {error, Err} if another error
%
% - 'ok' if succeed
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
			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				"FSM ~w reported that challenges are completed.",
				[ FsmPid ] ) ),
			ok;

		pending ->
			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				"FSM ~w reported that challenges are still pending.",
				[ FsmPid ] ) ),
			timer:sleep( 500 * ( MaxCount - Count + 1 ) ),
			wait_challenges_valid( FsmPid, Count - 1, MaxCount );

		{ _Other, Error } ->
			{ error, Error };

		% Happening if the ACME server was not able to download challenges, for
		% example if actually no relevant webserver is even running:
		%
		invalid ->
			throw( { challenges_could_not_be_validated, FsmPid } );

		UnexpectedState ->
			throw( { unexpected_checked_state, UnexpectedState, FsmPid  } )

	end.



% @doc Waits until the certification creation is reported as completed.
%
% Returns:
%
% - {error, timeout} if failed after X loops
%
% - {error, Err} if another error
%
% - {'ok', Response} if succeed
%
-spec wait_creation_completed( fsm_pid(), count() ) ->
		{ 'ok', map() } | { 'error', 'timeout' | any() }.
wait_creation_completed( FsmPid, C ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Waiting for the completion of the "
		"certificate creation...", [ FsmPid ] ) ),

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
			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				"End of waiting for creation of '~ts': read target status "
				"'finalize' for ~w.", [ BinCertFilePath, FsmPid ] ) ),
			Reply;

		creation_in_progress ->
			cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
				 "Still waiting for creation from ~w.", [ FsmPid ] ) ),
			timer:sleep( 500 * ( Max - Count + 1 ) ),
			wait_creation_completed( FsmPid, Count-1, Max );

		% Not expected to ever happen:
		Any ->
			trace_bridge:warning_fmt( "Received unexpected '~p' for ~w while "
				"waiting for creation (ignored).", [ Any, FsmPid ] ),
			wait_creation_completed( FsmPid, Count-1, Max )

	end.


% @doc Performs ACME authorization based on selected challenge initialization.
-spec perform_authorization( challenge_type(), [ bin_uri() ], le_state() ) ->
						{ { uri_challenge_map(), nonce() }, le_state() }.
perform_authorization( ChallengeType, AuthUris,
					   LEState=#le_state{ mode=Mode } ) ->

	cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
		"[~w] Starting authorization procedure with "
		"challenge type '~ts' (mode: ~ts).",
		[ self(), ChallengeType, Mode ] ) ),

	BinChallengeType = text_utils:atom_to_binary( ChallengeType ),

	{ { UriChallengeMap, Nonce }, FirstLEState } = perform_authorization_step1(
		AuthUris, BinChallengeType, LEState, _UriChallengeMap=#{} ),

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] URI challenge map after step 1:~n  ~p.",
		[ self(), UriChallengeMap ] ) ),

	% UriChallengeMap is like:
	%
	%  #{<<"ACME_BASE/acme/authz-v3/142509381">> =>
	%   #{<<"status">> => <<"pending">>,
	%     <<"token">> => <<"qVTq6gQWZO4Dt4gUmnaTQdwTRkpaSnMiRx8L7Grzhl8">>,
	%     <<"type">> => <<"http-01">>,
	%     <<"url">> =>
	%         <<"ACME_BASE/acme/chall-v3/142509381/-Axkdw">>}}.

	init_for_challenge_type( ChallengeType, Mode, FirstLEState,
							 UriChallengeMap ),

	{ NewNonce, SecondLEState } = perform_authorization_step2(
		maps:to_list( UriChallengeMap ), FirstLEState#le_state{ nonce=Nonce } ),

	{ { UriChallengeMap, NewNonce }, SecondLEState }.



% @doc Requests authorizations based on specified challenge type and URIs: for
% each challenge type (ex: http-01, dns-01, etc.), a challenge is proposed.
%
% At least in some cases, a single authorization URI is actually listed.
%
% Returns:
%   {ok, Challenges, Nonce} where:
%
%	- Challenges is map of Uri -> Challenge, where Challenge is of
%	 ChallengeType type
%
%	- Nonce is a new valid replay-nonce
%
-spec perform_authorization_step1( [ bin_uri() ], bin_challenge_type(),
		le_state(), uri_challenge_map() ) ->
			{ { uri_challenge_map(), nonce() }, le_state() }.
perform_authorization_step1( _AuthUris=[], _BinChallengeType,
		LEState=#le_state{ nonce=Nonce }, UriChallengeMap ) ->
	{ { UriChallengeMap, Nonce }, LEState };

perform_authorization_step1( _AuthUris=[ AuthUri | T ], BinChallengeType,
			LEState=#le_state{ nonce=Nonce, agent_private_key=PrivKey,
							   jws=Jws, cert_req_option_map=CertReqOptionMap },
			UriChallengeMap ) ->

	% Ex: AuthUri =
	%  "ACME_BASE/acme/authz-v3/133572032"

	{ { AuthMap, _LocUri, NewNonce }, ReqLEState } =
		leec_api:request_authorization( AuthUri, PrivKey,
							Jws#jws{ nonce=Nonce }, CertReqOptionMap, LEState ),

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"[~w] Step 1: authmap returned for URI '~ts':~n  ~p.",
		[ self(), AuthUri, AuthMap ] ) ),

	% Ex: AuthMap =
	% #{<<"challenges">> =>
	%	   [#{<<"status">> => <<"pending">>,
	%		  <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
	%		  <<"type">> => <<"http-01">>,
	%		  <<"url">> =>
	% <<"ACME_BASE/acme/chall-v3/133572032/Zu9ioQ">>},
	%		#{<<"status">> => <<"pending">>,
	%		  <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
	%		  <<"type">> => <<"dns-01">>,
	%		  <<"url">> =>
	% <<"ACME_BASE/acme/chall-v3/133572032/u9WbrQ">>},
	%		#{<<"status">> => <<"pending">>,
	%		  <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
	%		  <<"type">> => <<"tls-alpn-01">>,
	%		  <<"url">> =>
	% <<"ACME_BASE/acme/chall-v3/133572032/_WS56A">>}],
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
		ReqLEState#le_state{ nonce=NewNonce },
		UriChallengeMap#{ AuthUri => Challenge } ).



% @doc Second step of the authorization process, executed after challenge
% initialization.
%
% Notifies the ACME server the challenges are good to proceed, returns an
% updated nonce.
%
-spec perform_authorization_step2( [ { bin_uri(), challenge() } ],
								   le_state()) -> { nonce(), le_state() }.
perform_authorization_step2( _Pairs=[], LEState=#le_state{ nonce=Nonce } ) ->
	{ Nonce, LEState };

perform_authorization_step2( _Pairs=[ { Uri, Challenge } | T ],
			LEState=#le_state{ nonce=Nonce, agent_private_key=AgentPrivKey,
						   jws=Jws, cert_req_option_map=CertReqOptionMap } ) ->

	{ { Resp, _Location, NewNonce }, NotifLEState } =
		leec_api:notify_ready_for_challenge( Challenge, AgentPrivKey,
							Jws#jws{ nonce=Nonce }, CertReqOptionMap, LEState ),

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

	perform_authorization_step2( T, NotifLEState#le_state{ nonce=NewNonce } ).



% @doc Initializes the local configuration to serve the specified challenge
% type.
%
% Depends on challenge type and mode.
%
-spec init_for_challenge_type( challenge_type(), le_mode(), le_state(),
							   uri_challenge_map() ) -> void().
% Here we directly write challenges in a web root that is already being served
% through other means:
%
init_for_challenge_type( _ChallengeType='http-01', _Mode=webroot,
		LEState=#le_state{ webroot_dir_path=BinWebrootPath,
						   account_key=AccountKey },
		UriChallengeMap ) ->

	[ begin

		ChlgWebDir = file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

		file_utils:create_directory_if_not_existing( ChlgWebDir ),

		ChlgWebPath = file_utils:join( ChlgWebDir, Token ),

		Thumbprint = leec_jws:get_key_authorization( AccountKey, Token,
													 LEState ),

		% The default modes are fine:
		file_utils:write_whole( ChlgWebPath, Thumbprint )

	  end || #{ <<"token">> := Token } <- maps:values( UriChallengeMap ) ];


% Here we never write challenges, we trigger the user-specified callback
% whenever challenges are ready:
%
init_for_challenge_type( _ChallengeType, _Mode=slave, _LEState,
						 _UriChallengeMap ) ->
	ok;


% Here we spawn a dedicated (elli-based) webserver in order to host the
% challenges to be downloaded by the ACME server:
%
init_for_challenge_type( ChallengeType, _Mode=standalone,
		LEState=#le_state{ port=Port, domain=Domain, account_key=AccntKey },
		UriChallengeMap ) ->

	cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
		"Init standalone challenge for ~p.", [ ChallengeType ] ) ),

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
				[ { Token, leec_jws:get_key_authorization( AccntKey,
														Token, LEState ) }
				  || #{ <<"token">> := Token }
						 <- maps:values( UriChallengeMap ) ] ),

			{ ok, _ } = elli:start_link([
				{ name, { local, leec_elli_listener } },
				{ callback, leec_elli_handler },
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



% @doc Cleans up challenge context after it has been fullfilled (with success or
% not); in:
%
% - 'webroot' mode: delete token file
%
% - 'standalone' mode: stop internal webserver
%
% - 'slave' mode: nothing to do
%
-spec challenge_destroy( le_mode(), le_state() ) -> le_state().
challenge_destroy( _Mode=webroot,
				   LEState=#le_state{ webroot_dir_path=BinWPath,
									  challenges=UriChallengeMap } ) ->

	[ begin

		  ChalWebPath = file_utils:join(
						[ BinWPath, ?webroot_challenge_path, Token ] ),

		  file_utils:remove_file( ChalWebPath )

	  end || #{ <<"token">> := Token } <- maps:values( UriChallengeMap ) ],

	LEState#le_state{ challenges=#{} };


challenge_destroy( _Mode=standalone, LEState ) ->
	% Stop http server:
	elli:stop( leec_elli_listener ),
	LEState#le_state{ challenges=#{} };


challenge_destroy( _Modeslave, LEState ) ->
	LEState#le_state{ challenges=#{} }.
