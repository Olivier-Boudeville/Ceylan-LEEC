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
-author("Guillaume Bour <guillaume@bour.cc>").

% This fork:
-author("Olivier Boudeville <olivier.boudeville@esperide.com>").


% Replaces the deprecated gen_fsm; we use here the 'state_functions' callback
% mode, so:
%  - events are handled by one callback function *per state*
%  - state names must be atom-only
%
-behaviour(gen_statem).


% Public API:
-export([ start/1, get_default_options/0, get_default_options/1,
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
% URI format compatible with the shotgun library.


% Not involving Myriad's parse transform here:
-type maybe( T ) :: T | 'undefined'.
-type void() :: any().
-type table( K, V ) :: map_hashtable:map_hashtable( K, V ).

% To silence if not compiled with rebar3:
-export_type([ maybe/1, void/0, table/2 ]).


-type bin_domain() :: net_utils:bin_fqdn().

-type domain() :: net_utils:string_fqdn() | bin_domain().


% Three ways of interfacing with user code:
-type le_mode() :: 'webroot' | 'slave' | 'standalone'.


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
% Keys: <<"token">>, <<"url">>, 'thumbprint'.
%
-type challenge() :: table:table().


-type uri_challenge_map() :: table( bin_uri(), challenge() ).


-type type_challenge_map() :: table( challenge_type(), challenge() ).


% A user-specified option:
-type user_option() :: atom() | { atom(), any() }.


% User options.
%
% Known (atom) keys:
%  - async :: boolean()
%  - callback :: fun/1
%  - netopts :: map() => #{ timeout => non_neg_integer() }
%  - challenge :: challenge_type(), default being 'http-01'
%
-type option_id() :: 'async' | 'callback' | 'netopts' | 'challenge'.


% Storing user options.
%
% Known keys:
%  - async :: boolean() [if not defined, supposed true]
%  - callback :: fun/1
%  - netopts :: map() => #{ timeout => non_neg_integer() }
%  - challenge :: challenge_type()
%
-type option_map() :: table( option_id(), term() ).


% ACME operations that may be triggered.
%
% Known operations:
% - <<"newNonce">>
% - <<"newAccount">>
%
-type acme_operation() :: bin_string().


% ACME directory, converting operations into the URIs to access for them.
-type directory_map() :: table( acme_operation(), uri() ).

-type nonce() :: binary().


% Subject Alternative Name, i.e. values to be associated with a security
% certificate using a subjectAltName field; see
% https://en.wikipedia.org/wiki/Subject_Alternative_Name.
%
-type san() :: ustring().

-type bin_san() :: bin_string().


% JSON element decoded as a map:
-type json_map_decoded() :: map().


-type key_file_info() :: { 'new', file_name() } | file_path().


% A certificate, as a binary:
-type bin_certificate() :: binary().

% A key, as a binary:
-type bin_key() :: binary().

% A CSR key, as a binary:
-type bin_csr_key() :: bin_key().

-type jws_algorithm() :: 'RS256'.

% A binary encoded in base 64:
-type binary_b64() :: binary().

% Key authorization, a ninary made of a token and of the hash of a key
% thumbprint, once b64-encoded:
%
-type key_auth() :: binary().

% For the records introduced:
-include("letsencrypt.hrl").

-type tls_private_key() :: #tls_private_key{}.

-type key() :: #key{}.

-type jws() :: #jws{}.

-type certificate() :: #certificate{}.


-export_type([ bin_domain/0, domain/0, le_mode/0,
			   challenge_type/0, bin_challenge_type/0,
			   token/0, thumbprint/0, thumbprint_map/0,
			   string_uri/0, bin_uri/0, uri/0,
			   challenge/0, uri_challenge_map/0, type_challenge_map/0,
			   user_option/0, option_id/0, option_map/0,
			   acme_operation/0, directory_map/0, nonce/0,
			   san/0, bin_san/0, json_map_decoded/0, key_file_info/0,
			   bin_certificate/0, bin_key/0, bin_csr_key/0,
			   jws_algorithm/0, binary_b64/0, key_auth/0,
			   tls_private_key/0, key/0, jws/0, certificate/0 ]).


% Where Let's Encrypt will attempt to find answers to its challenges:
-define( webroot_challenge_path, <<".well-known/acme-challenge">> ).

% Base time-out, in milliseconds:
-define( base_timeout, 15000 ).



% State of a Let's Encrypt instance:
-record( le_state, {

	% ACME environment:
	env = prod :: 'staging' | 'prod',

	% ACME directory:
	directory_map = undefined :: maybe( directory_map() ),

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

	% Current nonce:
	nonce = undefined :: maybe( nonce() ),

	domain = undefined :: maybe( net_utils:bin_fqdn() ),

	sans = [] :: [ san() ],

	% TLS private key information:
	private_key = undefined :: maybe( tls_private_key() ),

	% JSON Web Signature of the private key:
	jws = undefined :: maybe( jws() ),

	account_key :: key(),

	order = undefined :: maybe( directory_map() ),

	% Known challenges, per URI:
	challenges = #{} :: uri_challenge_map(),

	% Path to certificate/csr key file:
	cert_key_file_path = undefined :: maybe( file_path() ),

	% API options:
	option_map = get_default_options() :: option_map()

}).

-type le_state() :: #le_state{}.

-type fsm_pid() :: pid().

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

-type action() :: gen_statem:action().



% Shorthands:

-type count() :: basic_utils:count().
-type error_term() :: basic_utils:error_term().

-type ustring() :: text_utils:ustring().
-type bin_string() :: text_utils:bin_string().

-type file_name() :: file_utils:file_name().
-type file_path() :: file_utils:file_path().

%-type directory_path() :: file_utils:directory_path().
-type bin_directory_path() :: file_utils:bin_directory_path().

-type base_status() :: basic_utils:base_status().

-type json() :: json_utils:json().



% Public API.


% Starts an instance of the letsencrypt service.
-spec start( [ user_option() ] ) -> { 'ok', fsm_pid() } | error_term().
start( UserOptions ) ->

	json_utils:start_parser(),

	% Not registered on purpose, to allow for concurrent ACME interactions
	% (i.e. multiple, parallel instances).
	%
	% Calls init/1 on the new process, and returns its outcome:
	%
	gen_statem:start_link( ?MODULE, UserOptions, _Opts=[] ).



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
	#{ async => Async, netopts => #{ timeout => 30000 } }.



% Generates, once started, asynchronously (in a non-blocking manner), a new
% certificate for the specified domain (FQDN).
%
% Parameters:
%	- Domain is the domain name to generate an ACME certificate for
%   - FsmPid is the PID of the FSM to rely on
%
% Returns:
%	- 'async' if async is set (the default being sync)
%	- {error, Err} if a failure happens
%
% Belongs to the user-facing API; requires the LEEC service to be already
% started.
%
-spec obtain_certificate_for( Domain :: domain(), fsm_pid() ) ->
									'async' | error_term().
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
		  { 'ok', certificate() } | 'async' | error_term().
obtain_certificate_for( Domain, FsmPid, OptionMap=#{ async := false } ) ->

	trace_utils:debug_fmt( "FSM ~w requested to generate sync certificate "
						   "for domain '~s'.", [ FsmPid, Domain ] ),

	% Direct synchronous return:
	obtain_cert_helper( Domain, FsmPid, OptionMap );


% Default to async=true:
obtain_certificate_for( Domain, FsmPid, OptionMap ) ->

	trace_utils:debug_fmt( "FSM ~w requested to generate async certificate "
						   "for domain '~s'.", [ FsmPid, Domain ] ),

	% Asynchronous (either already true, or set to true if not):
	_Pid = erlang:spawn_link( ?MODULE, obtain_cert_helper,
							  [ Domain, FsmPid, OptionMap#{ async => true } ] ),

	async.



% Stops the specified instance of letsencrypt service.
-spec stop( fsm_pid() ) -> void().
stop( FsmPid ) ->

	trace_utils:trace_fmt( "Requesting ~w to stop.", [ FsmPid ] ),

	% No more gen_fsm:sync_send_all_state_event/2 available, so
	% handle_call_for_all_states/4 will have to be called from all states
	% defined:
	%
	% (synchronous)
	%
	Res = gen_statem:call( _ServerRef=FsmPid, _Request=stop, ?base_timeout ),

	% Not stopped here, as stopping is only going back to the 'idle' state:
	%json_utils:stop_parser().

	trace_utils:trace_fmt( "FSM ~w stopped (result: ~p).", [ FsmPid, Res ] ).





% FSM internal API.


% Initializes the LEEC state machine:
% - init TLS private key and its JWS
% - fetch ACME directory
% - get valid nonce
%
% Transitions to the 'idle' initial state.
%
-spec init( [ user_option() ] ) ->
		{ 'ok', InitialStateName :: 'idle', InitialData :: le_state() }.
init( UserOptions ) ->

	LEState = setup_mode( get_options( UserOptions, _Blank=#le_state{} ) ),

	trace_utils:debug_fmt( "[~w] Initial state: ~p.", [ self(), LEState ] ),

	% Creates private key (a tls_private_key()) and initialises its JWS:
	PrivateKey = letsencrypt_tls:create_private_key(
		LEState#le_state.key_file_info, LEState#le_state.cert_dir_path ),

	KeyJws = letsencrypt_jws:init( PrivateKey ),

	OptionMap = LEState#le_state.option_map,

	URLDirectoryMap = letsencrypt_api:get_directory_map( LEState#le_state.env,
														 OptionMap ),

	FirstNonce = letsencrypt_api:get_nonce( URLDirectoryMap, OptionMap ),

	{ ok, _NewStateName=idle,
	  LEState#le_state{ directory_map=URLDirectoryMap,
						private_key=PrivateKey,
						jws=KeyJws,
						nonce=FirstNonce } }.



% One callback function per state, akin to gen_fsm:
-spec callback_mode() -> gen_statem:callback_mode().
callback_mode() ->
	state_functions.



% (spawn helper)
-spec obtain_cert_helper( Domain :: domain(), fsm_pid(), option_map() ) ->
		  { 'ok', certificate() } | error_term().
obtain_cert_helper( Domain, FsmPid, OptionMap=#{ async := Async } ) ->

	BinDomain = text_utils:ensure_binary( Domain ),

	Timeout = ?base_timeout,

	% Expected to trigger idle({create, BinDomain, Opts }, _, LEState):
	CreationRes = case gen_statem:call( _ServerRef=FsmPid,
				_Request={ create, BinDomain, OptionMap }, Timeout ) of

		% State of FSM shall thus be 'idle' now:
		ErrorTerm={ creation_failed, Error } ->
			trace_utils:error_fmt( "Creation error reported: ~p.", [ Error ] ),
			{ error, ErrorTerm };

		% State of FSM shall thus be 'pending' now; should then transition after
		% some delay to 'valid'; we wait for it:
		%
		creation_pending ->
			case wait_challenges_valid( FsmPid ) of

				ok ->
					% So here the FSM is expected to have switched from
					% 'pending' to 'valid'. Then:

					% Most probably 'finalize':
					Status = gen_statem:call( _ServerRef=FsmPid,
											  _Req=switchTofinalize, Timeout ),

					case wait_finalized( FsmPid, Status, _Count=20 ) of

						ok ->
							trace_utils:debug_fmt( "Domain '~s' finalized "
								"for ~w.", [ Domain, FsmPid ] ),
							ok;

						Error ->
							trace_utils:error_fmt( "Error for FSM ~w when "
								"finalizing domain '~s': ~p.",
								[ FsmPid, Domain, Error ] ),
							Error

					end;

				% Typically {error, timeout}:
				OtherError ->
					trace_utils:debug_fmt( "Reset of FSM ~w for '~s' "
						"after error ~p.", [ FsmPid, Domain, OtherError ] ),
					_ = gen_statem:call( _ServerRef=FsmPid, reset ),
					OtherError

			end;

		Other ->
			trace_utils:error_fmt( "Unexpected return after create for ~w: ~p",
								   [ FsmPid, Other ] ),
			throw( { unexpected_create, Other, FsmPid } )

	end,

	case Async of

		true ->
			Callback = maps:get( callback, OptionMap,
				_DefaultCallback=fun( Ret ) ->
					trace_utils:warning_fmt( "Default async callback called "
						"for ~w regarding result ~p.", [ FsmPid, Ret ] )
								 end ),

			Callback( CreationRes );

		_ ->
			ok

	end,

	%trace_utils:debug_fmt( "Return for domain '~s' creation (FSM: ~w): ~p",
	%                      [ Domain, FsmPid, CreationRes ] ),

	CreationRes.



% Returns the ongoing challenges with pre-computed thumbprints:
%   #{Challenge => Thumbrint} if ok,
%	'error' if fails
%
% Defined separately for testing.
%
-spec get_ongoing_challenges( fsm_pid() ) -> 'error' | thumbprint_map().
get_ongoing_challenges( FsmPid ) ->

	case catch gen_statem:call( _ServerRef=FsmPid,
								_Request=get_ongoing_challenges ) of

		% Process not started, wrong state, etc.:
		{ 'EXIT', ExitReason } ->
			trace_utils:error_fmt( "Challenge not obtained: ~p.",
								   [ ExitReason ] ),
			error;

		% Could be also 'no_challenge' if in 'idle' state.

		% Not a list thereof?
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



% State 'idle', the initial state, used when awaiting for certificate request.
%
% idle(get_ongoing_challenges): nothing done
%
-spec idle( event_type(), event_content(), le_state() ) ->
				  gen_statem:state_callback_result( action() ).
% idle with request {create, BinDomain, OptionMap}: starts the certificate
% creation procedure.
%
% Starts a new certificate delivery process:
%  - create new account
%  - create new order
%  - require authorization (returns challenges list)
%  - initiate chosen challenge
%
% Transition to:
%  - 'idle' if process failed
%  - 'pending' waiting for challenges to be complete
%
idle( _EventType={ call, From },
	  _EventContentMsg=_Request={ create, BinDomain, OptionMap },
	  _Data=LEState=#le_state{ directory_map=DirMap, private_key=PrivKey,
							   jws=Jws, nonce=Nonce } ) ->

	% Ex: 'http-01', 'tls-sni-01', etc.:
	ChallengeType = maps:get( challenge, OptionMap, _DefaultChlg='http-01' ),

	case ChallengeType of

		'http-01' ->
			ok;

		OtherChallengeType ->
			throw( { unsupported_challenge_type, OtherChallengeType } )

	end,

	{ AccountDecodedJsonMap, AccountLocationUri, AccountNonce } =
		letsencrypt_api:get_account( DirMap, PrivKey,
									 Jws#jws{ nonce=Nonce }, OptionMap ),

	AccountKeyAsMap = maps:get( <<"key">>, AccountDecodedJsonMap ),

	AccountKey = letsencrypt_tls:map_to_key( AccountKeyAsMap ),

	AccountJws = #jws{ alg=Jws#jws.alg, nonce=AccountNonce,
					   kid=AccountLocationUri },

	% Subject Alternative Names:
	Sans = maps:get( san, OptionMap, _DefaultSans=[] ),

	BinSans = text_utils:strings_to_binaries( Sans ),

	BinDomains = [ BinDomain | BinSans ],

	% TODO: checks order is ok
	{ OrderDecodedJsonMap, OrderLocationUri, OrderNonce } =
		letsencrypt_api:request_order( DirMap, BinDomains, PrivKey, AccountJws,
									   OptionMap ),

	% We need to keep trace of order location:
	LocOrder = OrderDecodedJsonMap#{ <<"location">> => OrderLocationUri },

	AuthLEState = LEState#le_state{ domain=BinDomain, jws=AccountJws,
		account_key=AccountKey, nonce=OrderNonce, sans=Sans },

	AuthUris = maps:get( <<"authorizations">>, OrderDecodedJsonMap ),

	AuthPair = perform_auth( ChallengeType, AuthUris, AuthLEState ),

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

	{ next_state, NewStateName, _NewData=FinalLEState,
	  _Action={ reply, From, Reply } };

idle( _EventType={ call, From },
	  _EventContentMsg=_Request=get_ongoing_challenges, _Data=_LEState ) ->

	trace_utils:warning_fmt( "Received a get_ongoing_challenges request event "
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
pending( _EventType={ call, From }, _EventContentMsg=get_ongoing_challenges,
		 _Data=LEState=#le_state{ account_key=AccountKey,
								  challenges=TypeChallengeMap } ) ->

	trace_utils:trace_fmt( "[~w] Getting ongoing challenges.", [ self() ] ),

	ThumbprintMap = maps:from_list( [ { Token,
		_Thumbprint=letsencrypt_jws:get_key_authorization( AccountKey, Token ) }
		  || #{ <<"token">> := Token } <- maps:values( TypeChallengeMap ) ] ),

	trace_utils:trace_fmt( "[~w] Returning from pending state challenge "
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
						  nonce=InitialNonce, private_key=PrivKey, jws=Jws,
						  option_map=OptionMap } ) ->

	trace_utils:trace_fmt( "[~w] Checking whether challenges are completed.",
						   [ self() ] ),

	% Checking the status for each authorization URI:
	{ NextStateName, ResultingNonce } = lists:foldl(

		fun( AuthUri, _Acc={ AccStateName, AccNonce } ) ->

			{ AuthJsonMap, _Location, NewNonce } =
					letsencrypt_api:request_authorization( AuthUri, PrivKey,
								   Jws#jws{ nonce=AccNonce }, OptionMap ),

			BinStatus = maps:get( <<"status">>, AuthJsonMap ),

			trace_utils:debug_fmt( "[~w] For auth URI ~s, received "
				"status '~w'.", [ self(), AuthUri, BinStatus ] ),

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
					trace_utils:warning_fmt( "[~w] For auth URI ~s, switching "
						"from '~s' to unsupported 'deactivated' state.",
						[ self(), AnyState, AuthUri ] ),
					deactivated;

				{ AnyState, <<"expired">> } ->
					trace_utils:warning_fmt( "[~w] For auth URI ~s, switching "
						"from '~s' to unsupported 'expired' state.",
						[ self(), AnyState, AuthUri ] ),
					expired;

				{ AnyState, <<"revoked">> } ->
					trace_utils:warning_fmt( "[~w] For auth URI ~s, switching "
						"from '~s' to unsupported 'revoked' state.",
						[ self(), AnyState, AuthUri ] ),
					revoked;

				% By default remains in the current state (including 'pending'):
				{ AccStateName, AnyBinStatus } ->
					trace_utils:trace_fmt( "[~w] For auth URI ~s, staying "
						"in '~s' despite having received status '~p'.",
						[ self(), AuthUri, AccStateName, AnyBinStatus ] ),
					AccStateName;

				{ AnyOtherState, UnexpectedBinStatus } ->
					trace_utils:error_fmt( "[~w] For auth URI ~s, "
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

	trace_utils:debug_fmt( "[~w] Check resulted in switching from 'pending' "
						   "to '~s' state.", [ self(), NextStateName ] ),

	{ next_state, NextStateName,
	  _NewData=LEState#le_state{ nonce=ResultingNonce },
	  _Action={ reply, From, _RetValue=NextStateName } };


% Possibly switchTofinalize:
pending( _EventType={ call, From }, _EventContentMsg=_Request=switchTofinalize,
		 _Data=_LEState ) ->

	trace_utils:trace_fmt( "[~w] Received, while in 'pending' state, "
		"request '~s' from ~w, currently ignored.", [ self(), From ] ),

	% { next_state, finalize, ...}?

	keep_state_and_data;

pending( _EventType={ call, ServerRef }, _EventContentMsg=Request,
		 _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=pending,
								LEState );

pending( EventType, EventContentMsg, _LEState ) ->

	trace_utils:warning_fmt( "[~w] Received, while in 'pending' state, "
		"event type '~p' and content message '~p'.",
		[ self(), EventType, EventContentMsg ] ),

	throw( { unexpected_event, EventType, EventContentMsg,
			 { state, pending } } ).



% Management of the 'valid' state.
%
% When challenges have been successfully completed, finalizes ACME order and
% generates TLS certificate.
%
% Returns Status, the order status.
%
% Transitions to 'finalize' state.
%
valid( _EventType={ call, _ServerRef=From },
	   _EventContentMsg=_Request=switchTofinalize,
	   _Data=LEState=#le_state{ mode=Mode, domain=BinDomain, sans=SANs,
			cert_dir_path=BinCertDirPath, order=OrderDirMap,
			private_key=PrivKey, jws=Jws, nonce=Nonce,
			option_map=OptionMap } ) ->

	challenge_destroy( Mode, LEState ),

	KeyFilename = text_utils:binary_to_string( BinDomain ) ++ ".key",

	% KeyFilePath is required for csr generation:
	CreatedTLSPrivKey = letsencrypt_tls:create_private_key(
						  { new, KeyFilename }, BinCertDirPath ),

	Csr = letsencrypt_tls:get_cert_request( BinDomain, BinCertDirPath, SANs ),

	{ FinOrderDirMap, _BinUri, FinNonce } = letsencrypt_api:finalize_order(
		OrderDirMap, Csr, PrivKey, Jws#jws{ nonce=Nonce }, OptionMap ),

	BinStatus = case maps:get( <<"status">>, FinOrderDirMap,
							   undefined_status ) of

		undefined_status ->
			throw( { lacking_status, FinOrderDirMap } );

		S ->
			S

	end,

	% Expected to be 'finalize':
	NewStateName = case letsencrypt_api:binary_to_status( BinStatus ) of

		finalize ->
			finalize;

		OtherStateName ->
			trace_utils:warning_fmt( "New state after finalizing order is not "
				"'finalize' but '~s'.", [ OtherStateName ] ),
			OtherStateName

	end,

	% Update location in finalized order:
	LocOrderDirMap = FinOrderDirMap#{
				   <<"location">> => maps:get( <<"location">>, OrderDirMap ) },

	FinalLEState = LEState#le_state{ order=LocOrderDirMap,
		cert_key_file_path=CreatedTLSPrivKey#tls_private_key.file_path,
		nonce=FinNonce },

	{ next_state, NewStateName, _NewData=FinalLEState,
	  _Action={ reply, From, _Reply=NewStateName } };


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
% Wait for certificate generation being complete (order status == 'valid').
%
% Returns the order status.
%
% Transitions to:
%   state 'processing' : still ongoing
%   state 'valid'      : certificate is ready
%
finalize( _EventType=processing, _EventContentMsg=_Domain,
		  _Data=LEState=#le_state{ order=OrderMap, private_key=PrivKey,
							jws=Jws, nonce=Nonce, option_map=OptionMap } ) ->

	Loc = maps:get( <<"location">>, OrderMap, nil ),

	{ NewOrderMap, _Loc, NewNonce } = letsencrypt_api:get_order( Loc, PrivKey,
										 Jws#{ nonce => Nonce }, OptionMap ),

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
finalize( _EventType=valid, _EventContentMsg=_Domain,
		  _Data=LEState=#le_state{ order=OrderMap, domain=BinDomain,
			cert_key_file_path=KeyFilePath, cert_dir_path=BinCertDirPath,
			private_key=PrivKey, jws=Jws, nonce=Nonce,
			option_map=OptionMap } ) ->

	BinKeyFilePath = text_utils:string_to_binary( KeyFilePath ),

	% Downloads certificate:
	BinCert = letsencrypt_api:get_certificate( OrderMap, PrivKey,
							Jws#{ nonce => Nonce }, OptionMap ),

	Domain = text_utils:binary_to_string( BinDomain ),

	CertFilePath = letsencrypt_tls:write_certificate( Domain, BinCert,
													  BinCertDirPath ),

	BinCertFilePath = text_utils:string_to_binary( CertFilePath ),

	{ reply, { ok, #{ key => BinKeyFilePath, cert => BinCertFilePath } }, idle,
	  LEState#le_state{ nonce=undefined } };

finalize( _EventType={ call, ServerRef }, _EventContentMsg=Request,
		  _Data=LEState ) ->
	handle_call_for_all_states( ServerRef, Request, _StateName=finalize,
								LEState );


finalize( UnexpectedEventType, EventContentMsg, _LEState ) ->

	trace_utils:error_fmt( "Unknown event ~p (content: ~p) in finalize status.",
						  [ UnexpectedEventType, EventContentMsg ] ),

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
	Res = StateName,
	{ keep_state_and_data, _Actions={ reply, _From=ServerRef, Res } };


handle_call_for_all_states( ServerRef, _Request=stop, StateName,
							LEState=#le_state{ mode=Mode } ) ->

	trace_utils:debug_fmt( "[~w] Received a stop request from ~s state.",
						   [ ServerRef, StateName ] ),

	challenge_destroy( Mode, LEState ),

	% Stopping is just returning back to idle (no action):

	%{ stop_and_reply, _Reason, _Reply={ reply, ServerRef, ok },
	%   _Data=LEState }.

	{ next_state, _NextState=idle, _NewData=LEState };


handle_call_for_all_states( ServerRef, Request, StateName, _LEState ) ->

	trace_utils:error_fmt( "[~w] Received an unexpected request, ~p, "
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
%   - staging: runs in staging environment (otherwise running in production)
%   - key_file_path: reuse an existing TLS key
%   - cert_dir_path: path to read/save TLS certificates, keys and csr requests
%   - http_timeout: timeout for ACME API requests (in seconds)
%
% Returns LEState (type record 'le_state') filled with corresponding options
% values.
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
			throw( { invalid_mode, Mode } )

	end,
	get_options( T, LEState#le_state{ mode=Mode } );

get_options( _Opts=[ { key_file_path, KeyFilePath } | T ], LEState ) ->
	get_options( T, LEState#le_state{ key_file_info=KeyFilePath } );

get_options( _Opts=[ { cert_dir_path, CertDirPath } | T ], LEState ) ->
	get_options( T, LEState#le_state{
				  cert_dir_path=text_utils:string_to_binary( CertDirPath ) } );

get_options( _Opts=[ { webroot_dir_path, WebDirPath } | T ], LEState ) ->
	get_options( T, LEState#le_state{
				  webroot_path=text_utils:string_to_binary( WebDirPath ) } );

get_options( _Opts=[ { port, Port } | T ], LEState ) when is_integer( Port ) ->
	get_options( T, LEState#le_state{ port=Port } );

get_options( _Opts=[ { http_timeout, Timeout } | T ], LEState ) ->
	get_options( T, LEState#le_state{
				  option_map=#{ netopts => #{ timeout => Timeout } } } );

get_options( _Opts=[ Unexpected | _T ], _LEState ) ->
	trace_utils:error_fmt( "Invalid option: ~p.", [ Unexpected ] ),
	throw( { invalid_option, Unexpected } ).



% Setups the context of chosen mode.
-spec setup_mode( le_state() ) -> le_state().
setup_mode( #le_state{ mode=webroot, webroot_path=undefined } ) ->
	trace_utils:error( "Missing 'webroot_path' parameter." ),
	throw( webroot_path_missing );

setup_mode( LEState=#le_state{ mode=webroot, webroot_path=BinWebrootPath } ) ->

	ChallengeDirPath =
		file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

	% TODO: check directory is writable.
	file_utils:create_directory_if_not_existing( ChallengeDirPath,
												 create_parents ),

	LEState;

setup_mode( LEState=#le_state{ mode=standalone, port=Port } )
  when is_integer( Port ) ->
	% TODO: check port is unused?
	LEState;

setup_mode( LEState=#le_state{ mode=slave } ) ->
	LEState;

% Every other mode value is invalid:
setup_mode( #le_state{ mode=Mode } ) ->
	trace_utils:error_fmt( "Invalid '~p' mode.", [ Mode ] ),
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
				_Request=check_challenges_completed, _Timeout=15000 ) of

		valid ->
			ok;

		pending ->
			timer:sleep( 500 * ( MaxCount - Count + 1 ) ),
			wait_challenges_valid( FsmPid, Count - 1, MaxCount );

		{ _Other, Error } ->
			{ error, Error };

		UnexpectedState ->
			throw( { unexpected_checked_state, UnexpectedState } )

	end.



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
-spec wait_finalized( fsm_pid(), status(), count(), count() ) ->
		  { 'ok', map() } | { 'error', 'timeout' | any() }.
wait_finalized( _FsmPid, _Status, _Count=0, _Max ) ->
	{ error, timeout };

wait_finalized( FsmPid, Status, Count, Max ) ->

	case gen_statem:call( FsmPid, _Req=get_status, ?base_timeout ) of

		Status ->
			ok;

		S when S =:= valid orelse S =:= processing ->
			timer:sleep( 500 * ( Max - Count + 1 ) ),
			wait_finalized( FsmPid, S, Count-1, Max );

		P={ _, Error } ->
			trace_utils:error_fmt( "wait_finalized received ~p for ~w.",
								   [ P, FsmPid ] ),
			{ error, Error };

		Any ->
			trace_utils:warning_fmt( "wait_finalized received ~p for ~w.",
									 [ any, FsmPid ] ),
			Any

	end.



% Performs ACME authorization based on selected challenge initialization.
-spec perform_auth( challenge_type(), [ bin_uri() ], le_state() ) ->
						  { uri_challenge_map(), nonce() }.
perform_auth( ChallengeType, AuthUris, LEState=#le_state{ mode=Mode } ) ->

	trace_utils:trace_fmt( "[~w] Starting authorization procedure with "
		"challenge type '~s' (mode: ~s).", [ self(), ChallengeType, Mode ] ),

	BinChallengeType = text_utils:atom_to_binary( ChallengeType ),

	{ UriChallengeMap, Nonce } = perform_auth_step1( AuthUris, BinChallengeType,
											 LEState, _UriChallengeMap=#{} ),

	trace_utils:debug_fmt( "[~w] URI challenge map after step 1:~n ~p.",
						   [ self(), UriChallengeMap ] ),

	init_for_challenge_type( ChallengeType, Mode, LEState, UriChallengeMap ),

	NewNonce = perform_auth_step2( maps:to_list( UriChallengeMap ),
								   LEState#le_state{ nonce=Nonce } ),

	{ UriChallengeMap, NewNonce }.



% Requests authorizations based on specified challenge type and URIs.
%
% Returns:
%   {ok, Challenges, Nonce}
%		- Challenges is map of Uri -> Challenge, where Challenge is of
%		ChallengeType type
%		- Nonce is a new valid replay-nonce
%
-spec perform_auth_step1( [ bin_uri() ], bin_challenge_type(), le_state(),
		  uri_challenge_map() ) -> { uri_challenge_map(), nonce() }.
perform_auth_step1( _AuthUris=[], _BinChallengeType, #le_state{ nonce=Nonce },
					UriChallengeMap ) ->
	{ UriChallengeMap, Nonce };

perform_auth_step1( _AuthUris=[ AuthUri | T ], BinChallengeType,
			LEState=#le_state{ nonce=Nonce, private_key=PrivKey,
							   jws=Jws, option_map=OptionMap },
			UriChallengeMap ) ->

	% Ex: AuthUri =
	%  https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/133572032

	{ AuthMap, _LocUri, NewNonce } = letsencrypt_api:request_authorization(
		AuthUri, PrivKey, Jws#jws{ nonce=Nonce }, OptionMap ),

	trace_utils:debug_fmt( "[~w] Step 1: authmap returned for URI '~s':~n ~p.",
						   [ self(), AuthUri, AuthMap ] ),

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

	% Retains only the specified challenge type (cannot be a list
	% comprehension):
	%
	[ Challenge ] = lists:filter(

		fun( ChlgMap ) ->
			maps:get( <<"type">>, ChlgMap, _Default=error ) =:= BinChallengeType
		end,

		_List=maps:get( <<"challenges">>, AuthMap ) ),

	perform_auth_step1( T, BinChallengeType, LEState#le_state{ nonce=NewNonce },
						UriChallengeMap#{ AuthUri => Challenge } ).



% Second step of the authorization process, executed after challenge
% initialization.
%
% Notifies the ACME server the challenges are good to proceed, returns an
% updated nonce.
%
-spec perform_auth_step2( [ { bin_uri(), challenge() } ], le_state()) ->
								nonce().
perform_auth_step2( _Pairs=[], #le_state{ nonce=Nonce } ) ->
	Nonce;

perform_auth_step2( _Pairs=[ { _Uri, Challenge } | T ],
					LEState=#le_state{ nonce=Nonce, private_key=PrivKey,
									   jws=Jws, option_map=OptionMap } ) ->

	{ _Resp, _Location, NewNonce } =
		letsencrypt_api:notify_ready_for_challenge( Challenge, PrivKey,
										Jws#jws{ nonce=Nonce }, OptionMap ),

	perform_auth_step2( T, LEState#le_state{ nonce=NewNonce } ).



% Initializes the local configuration to serve the specified challenge type.
%
% Depends on challenge type and mode.
%
-spec init_for_challenge_type( challenge_type(), le_mode(), le_state(),
							   uri_challenge_map() ) -> void().
init_for_challenge_type( _ChallengeType='http-01', _Mode=webroot,
		#le_state{ webroot_path=BinWebrootPath, account_key=AccountKey },
		UriChallengeMap ) ->

	[ begin

		ChlgWebDir = file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

		file_utils:create_directory_if_not_existing( ChlgWebDir ),

		ChlgWebPath = file_utils:join( ChlgWebDir, Token ),

		Thumbprint = letsencrypt_jws:get_key_authorization( AccountKey, Token ),

		% Hopefully the default modes are fine:
		file_utils:write_whole( ChlgWebPath, Thumbprint, _Modes=[] )

	  end || #{ <<"token">> := Token } <- maps:values( UriChallengeMap ) ];


init_for_challenge_type( _ChallengeType, _Mode=slave, _LEState,
						 _UriChallengeMap ) ->
	ok;

init_for_challenge_type( ChallengeType, _Mode=standalone,
			#le_state{ port=Port, domain=Domain, account_key=AccntKey },
			UriChallengeMap ) ->

	%trace_utils:debug_fmt( "Init standalone challenge for ~p.",
	%                       [ ChallengeType ] ),

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
																  Token ) }
				  || #{ <<"token">> := Token }
						 <- maps:values( UriChallengeMap ) ] ),

			{ ok, _ } = elli:start_link([
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



% Cleans up challenge context after it has been fullfilled (with success or
% not); in:
% - 'webroot' mode: delete token file
% - 'standalone' mode: stop internal webserver
% - 'slave' mode: nothing to do
%
-spec challenge_destroy( le_mode(), le_state() ) -> void().
challenge_destroy( _Mode=webroot,
		#le_state{ webroot_path=BinWPath, challenges=UriChallengeMap } ) ->

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
