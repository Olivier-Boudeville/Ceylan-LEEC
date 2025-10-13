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

% Copyright (C) 2020-2025 Olivier Boudeville
%
% This file is part of the Ceylan-LEEC library, a fork of the Guillaume Bour's
% letsencrypt-erlang library, released under the same licence.
%
% Creation date: 2020.

-module(leec).

-moduledoc """
**Main module of LEEC**, the Ceylan Let's Encrypt Erlang fork; see
[http://leec.esperide.org] for more information.

Original 'Let's Encrypt Erlang' application:
[https://github.com/gbour/letsencrypt-erlang].
""".


% Original work:
-author("Guillaume Bour (guillaume at bour dot cc)").

% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com)").



% Usage notes:
%
% The caller processes may choose to catch exceptions (notably of the exit
% class), as gen_statem calls may issue them, typically because of a time-out.
%
% Possibly LEEC should catch such exceptions and return a
% basic_utils:base_outcome() result.


% Callers may also trap EXIT messages, even if those are not specifically
% expected.


% Replaces the deprecated gen_fsm; we use here the 'state_functions' callback
% mode, so:
%  - events are handled by one callback function *per state*
%  - state names must be atom-only
%
-behaviour(gen_statem).


% This is a (passive) application:
%
% (the signatures do not seem to be respected here due to a clash in the start/*
% functions)
%
-behaviour(application).


% Public API:
-export([ get_ordered_prerequisites/0,
          is_known_challenge_type/1,
          can_perform_dns_challenges/0,
          is_supported_dns_provider/1,
          reset_state/2,
          start/2, start/3,
          get_default_cert_request_options/1,
          get_default_cert_request_options/2,
          obtain_certificate_for/2, obtain_certificate_for/3,
          stop/1, terminate/1 ]).


% For testing purpose:
-export([ get_ongoing_challenges/1, send_ongoing_challenges/2,
          get_agent_key_path/1 ]).


% Facilities:
-export([ dns_provider_to_string/1, get_credentials_path_for/3,
          get_certificate_priv_key_filename/1,
          caller_state_to_string/1, maybe_caller_state_to_string/1 ]).


% For spawn purpose:
-export([ obtain_cert_helper/5 ]).


% FSM gen_statem based API:
-export([ init/1, callback_mode/0, terminate/3, code_change/4 ]).


% FSM state-corresponding callbacks:
-export([ idle/3, pending/3, valid/3, finalize/3, invalid/3 ]).

-export([ state_to_string/1 ]).


% For myriad_spawn*:
-include_lib("myriad/include/spawn_utils.hrl").


% Design notes:
%
% For all challenges, starting LEEC returns a caller state, which contains
% notably the PID of a process in charge of the certificate creation, typically
% a FSM.
%
% This is indeed a FSM (gen_statem) for the http-01 challenge but, at least
% currently, it is a mere intermediary process for the dns-01 challenge, which
% is only in charge of running certbot.
%
% The idea is that if, in the future, a full implementation of dns-01 is done
% (like for http-01), then certbot will be dropped but the LEEC API may
% (hopefully) not change.



% Implementation notes:
%
% Multiple FSM (Finite State Machines) can be spawned, for parallel certificate
% management; so such a FSM is not registered as a singleton anymore.

% Similarly, no more ETS-based connection pool, as it would be shared between
% concurrent FSMs, whereas each connection is private to a given FSM. Instead an
% (explicit) per-FSM TCP cache is managed.


% The URI format compatible with the shotgun library.
%
% The netopts map (in the option map) possibly just contains a time-out, or
% maybe SSL options; it is a parameter directly needed as such by
% shotgun:post/5.

-type bin_uri() :: web_utils:bin_uri().

-type bin_domain() :: net_utils:bin_fqdn().

-type domain_name() :: net_utils:string_fqdn() | bin_domain().



-doc """
Three ways of interfacing LEEC with user code.

We mostly concentrated on the slave one.
""".
-type web_interfacing_mode() ::
    'webroot'     % If using a third-party webserver (e.g. Apache)
  | 'slave'       % If LEEC is driven by the caller (e.g. US-Web)
  | 'standalone'. % If letting LEEC handle the web dance
                  % (with the Elli webserver)


-doc "The PID of a LEEC FSM.".
-type fsm_pid() :: pid().



-doc """
These are CA (Certificate Authorities).

Other certificate providers (e.g. ZeroSSL) may be added in the future.
""".
-type certificate_provider() :: 'letsencrypt'.



-doc """
The types of certificates that can requested from a certificate authority.

Depending on the target certificate type, different challenges will be used.

DNS names in certificates may only have a single wildcard character, and it must
be the entire leftmost DNS label, for instance `"*.foobar.org"`.
""".
-type certificate_type() ::

    'single_domain' % Possibly with different names, i.e. SANs
                    % (Subject Alternative Name); based on the http-01
                    % challenge.

  | 'wildcard_domain'. % To authenticate any DNS name matching the wildcard
                       % name; based on the dns-01 challenge.



-doc "The type of challenges supported.".
-type challenge_type() ::
    'http-01'     % Supported internally.
  | 'dns-01'      % Supported based on certbot.
  | 'tls-sni-01'. % Not supported.



-doc "Challenge type, as a binary string.".
-type bin_challenge_type() :: bin_string().



-doc """
The ACME environments.

Production is `default` in ACME parlance.
""".
-type environment() :: 'staging' | 'production'.



-doc """
A path to a PEM-encoded ("Privacy Enhanced Mail", a rather misleading naming)
file may contain just a public certificate, or an entire certificate chain
including the public key, private key, and root certificates (which is
preferrable), or even just a certificate request.

This is a text file containing sections like `"-----BEGIN CERTIFICATE-----"`,
`"-----BEGIN PRIVATE KEY-----"`, etc.

Its extension may be `".pem"`.
""".
-type pem_file_path() :: bin_file_path().



-doc """
A PEM-encoded file containing the actual certificate of interest.

Typical names for such files may be `"fullchain.pem"`, `"cert.pem"` or
`"MYDOMAIN.crt"`.
""".
-type cert_file_path() :: pem_file_path().



-doc """
A PEM-encoded file containing the private key corresponding to a certificate,
as securely sent back by an ACME server.

Such a key must be strongly secured.

Typical names for such files may be `"privkey.pem"` or `"MYDOMAIN.key"`.
""".
-type cert_priv_key_file_path() :: pem_file_path().


-export_type([ pem_file_path/0, cert_file_path/0, cert_priv_key_file_path/0,
               leec_caller_state/0,
               start_outcome/0, obtain_outcome/0, obtained_outcome/0,
               creation_outcome/0 ]).



% Supposedly:
-type token() :: ustring().


-doc "A JSON-encoded key.".
-type thumbprint() :: json().



-doc "Associating tokens with keys.".
-type thumbprint_map() :: table( token(), thumbprint() ).



-doc "For the reuse of TCP connections to the ACME server.".
-type tcp_connection_cache() :: table( { web_utils:protocol_type(),
        net_utils:string_host_name(), tcp_port() }, shotgun:connection() ).



% ACME_BASE below can be for example
% https://acme-staging-v02.api.letsencrypt.org, ACME_COMM being
% https://community.letsencrypt.org.


-doc """
All known information regarding a challenge.

As Key => example of associated value:

- `<<"status">> => <<"pending">>`

- `<<"token">> => <<"qVTx6gQWZO4Dt4gUmnaTQdwTRkpaSnMiRx8L7Grzhl8">>`

- `<<"type">> => <<"http-01">>`

- `<<"url">> =>
    <<"ACME_BASE/acme/chall-v3/132509381/-Axkdw">>`
""".
-type challenge() :: table( bin_string(), bin_string() ).


-type uri_challenge_map() :: table( bin_uri(), challenge() ).

-type type_challenge_map() :: table( challenge_type(), challenge() ).

-type order_map() :: table( bin_string(), bin_uri() ).



-doc "A user-specified LEEC start option.".
-type start_option() ::
    start_common_option()
  | start_http_01_option() % for single-domain certificates
  | start_dns_01_option(). % for wildcard certificates



-doc "Options common to all challenge types.".
-type start_common_option() ::

    % By default the 'production' environment is used:
    { 'environment', environment() }

    % The work directory in which LEEC is to write working data (e.g. logs); it
    % must therefore be writable by the current user.
    %
    % The default work directory is the current directory.
    %
  | { 'work_dir_path', any_directory_path() }

    % The private key that shall be used to authenticate this agent to the ACME
    % server (not the certificate private key):
    %
  | { 'agent_key_file_path', any_file_path() }

    % The directory in which the obtained certificates will be made available.
    %
    % The default certificate directory is the current directory.
    %
  | { 'cert_dir_path', any_directory_path() }

  | { 'http_timeout', milliseconds() }.



-doc """
Options associated to the `http-01` challenge, for single-domain certificates.
""".
-type start_http_01_option() ::
    { 'interfacing_mode', web_interfacing_mode() }
  | { 'webroot_dir_path', any_directory_path() }
  | { 'port', tcp_port() }.



-doc "Options associated to the `dns-01` challenge, for wildcard certificates.".
-type start_dns_01_option() ::

    % The DNS provider where an entry will have to be updated for the challenge:
    { 'dns_provider', dns_provider() }

    % The directory in which the DNS credentials will be looked up:
  | { 'cred_dir_path', any_directory_path() }.



-doc "The known and supported DNS providers.".
-type dns_provider() :: 'ovh'.



-doc """
A path to a file containing LEEC-related credentials.

See [https://leec.esperide.org/#credentials-file].
""".
-type credentials_path() :: any_file_path().



-doc "Certificate request options.".
-type cert_req_option_id() :: 'async' | 'callback' | 'netopts'
                            | 'challenge_type' | 'sans' | 'json'.



-doc """
A function executed when a domain certificate has been successfully obtained
asynchronously.
""".
-type creation_callback() :: fun( (obtain_outcome() ) -> void() ).



-doc """
Storing certificate request options.

Known (atom) keys:

 - options common for all certificate requests:

   - async :: boolean():
      - if true (the default), immediately returns, and a callback will be
      triggered once the certificate is obtained
      - if false, blocks until completed, and returns the path to the
      generated certificate

   - callback :: creation_callback() -> void(): the function executed when
   Async is true, once the domain certificate has been successfully obtained

 - options for http-01 certificate requests:
   - netopts :: map() => #{ timeout => milliseconds(),
                            ssl => [ssl:client_option()] }:
     to specify an HTTP timeout or SSL client options

   - sans :: [any_san()]: a list of the Subject Alternative Names for that
     certificate (if single-domain, not wildcard)

 - options for dns-01 certificate requests:

   - email: email address used for registration and recovery contact
   (otherwise specifying leec-certificates@DOMAIN)

 - not to be set by the user:

   - json :: boolean()

   - challenge_type :: challenge_type() is the type of challenge to rely on
   when interacting with the ACME server
""".
-type cert_req_option_map() :: table( cert_req_option_id(), term() ).



-doc """
ACME operations that may be triggered.

Known operations:
- `<<"newAccount">>`
- `<<"newNonce">>`
- `<<"newOrder">>`
- `<<"revokeCert">>`
""".
-type acme_operation() :: bin_string().



-doc """
ACME directory, converting operations to trigger into the URIs to access for
them.
""".
-type directory_map() :: table( acme_operation(), bin_uri() ).



-doc """
An arbitrary binary that can be used just once in a cryptographic communication.
""".
-type nonce() :: binary().



-doc """
Subject Alternative Name, i.e. values to be associated with a security
certificate using a subjectAltName field.

See [https://en.wikipedia.org/wiki/Subject_Alternative_Name].
""".
-type san() :: ustring().

-type bin_san() :: bin_string().

-type any_san() :: san() | bin_san().



-doc "JSON element decoded as a map.".
-type json_map_decoded() :: map().



-doc """
Information regarding the private key of the LEEC agent.

(if `new` is used, the path is supposed to be either absolute, or relative to
the certificate directory)
""".
-type agent_key_file_info() :: { 'new', bin_file_path() } | bin_file_path().



-doc "A certificate, as a binary.".
-type bin_certificate() :: binary().



-doc "A key, as a binary.".
-type bin_key() :: binary().



-doc "A CSR key, as a binary.".
-type bin_csr_key() :: bin_key().



-doc "Element of a key.".
-type key_integer() :: integer() | binary().



-doc """
Description of a RSA private key.

(as `crypto:rsa_private()` is not exported)
""".
-type rsa_private_key() :: [ key_integer() ].



-type jws_algorithm() :: 'RS256'.



-doc "A binary that is encoded in base 64.".
-type binary_b64() :: binary().



-doc """
Key authorization, a binary made of a token and of the hash of a key thumbprint,
once b64-encoded.
""".
-type key_auth() :: binary().



% For the records introduced:
-include("leec.hrl").



-doc """
The TLS private key (locally generated and never sent) of the target
certificate.
""".
-type tls_private_key() :: #tls_private_key{}.



-doc "The TLS public key (locally generated) of the target certificate.".
-type tls_public_key() :: #tls_public_key{}.


-type tls_csr() :: binary_b64().

-type jws() :: #jws{}.



-doc "Any type of LEEC state.".
-type leec_state() :: leec_http_state() | leec_dns_state().



-doc """
LEEC state for the `http-01` challenge.

Needed by other LEEC modules.
""".
-type leec_http_state() :: #leec_http_state{}.



-doc """
LEEC state for the `dns-01` challenge.

Needed by other LEEC modules.
""".
-type leec_dns_state() :: #leec_dns_state{}.



-export_type([ bin_uri/0, bin_domain/0, domain_name/0,
               web_interfacing_mode/0, fsm_pid/0,
               certificate_provider/0, certificate_type/0,
               challenge_type/0, bin_challenge_type/0,
               environment/0,
               token/0, thumbprint/0, thumbprint_map/0, tcp_connection_cache/0,
               challenge/0, uri_challenge_map/0, type_challenge_map/0,
               order_map/0,

               start_option/0, start_common_option/0, start_http_01_option/0,
               start_dns_01_option/0,

               dns_provider/0, credentials_path/0,

               cert_req_option_id/0, cert_req_option_map/0, creation_callback/0,
               acme_operation/0, directory_map/0, nonce/0,
               san/0, bin_san/0, any_san/0,
               json_map_decoded/0, agent_key_file_info/0,
               bin_certificate/0, bin_key/0, bin_csr_key/0,
               key_integer/0, rsa_private_key/0,
               jws_algorithm/0, binary_b64/0, key_auth/0,
               tls_private_key/0, tls_public_key/0, tls_csr/0,
               jws/0,
               leec_state/0, leec_http_state/0, leec_dns_state/0,
               status/0, request/0 ]).


% Where Let's Encrypt will attempt to find answers to its http-01 challenges:
-define( webroot_challenge_path, <<".well-known/acme-challenge">> ).


% Default overall http time-out, in milliseconds (8 minutes):
-define( default_timeout, 8 * 60 * 1000 ).


% Base time-out, in milliseconds:
-define( base_timeout, ?default_timeout div 2 ).


% Where certbot is to store its internal state (i.e. where it creates the
% 'renewal-hooks', 'renewal', 'accounts', 'archive' and 'live' directories):
%
% (a specific name for clarity and to avoid removing any non-LEEC data)
%
-define( certbot_state_dir, <<"leec-certbot-internal-state">> ).



-doc "Typically fsm_pid().".
-type server_ref() :: gen_statem:server_ref().



-type state_callback_result() ::
        fsm_utils:state_callback_result( gen_statem:action() ).



-doc "LEEC FSM status (corresponding to state names).".
-type status() :: 'pending' | 'processing' | 'valid' | 'invalid' | 'revoked'.



-type request() :: atom().

-type state_name() :: status().

-type event_type() :: gen_statem:event_type().

-type event_content() :: term().



-doc """
The minimal LEEC state returned to the caller.

Not to be mixed up with the internal state of LEEC FSMs.
""".
-type leec_caller_state() :: { challenge_type(), fsm_pid() }.



-doc """
Returned value after starting LEEC.

In practice, for all challenges: either an error or `{ok, LeecCallerState}`.
""".
-type start_outcome() :: { 'ok', leec_caller_state() }
                       | basic_utils:tagged_error().
                         %'ok' | gen_statem:start_ret().



-doc """
The (internal) value returned by a FSM / a bot about an attempt of certification
creation.
""".
-type creation_outcome() ::
    { 'certificate_ready', cert_file_path(), cert_priv_key_file_path() }
  | tagged_error(). % That is: {'error', term()}



-doc """
Returned user-targeted value (either as a message or as the argument of a
callback) after having sent a request to obtain a certificate.

Defined to differentiate from `creation_outcome()` and gather all possible error
terms.
""".
-type obtained_outcome() ::
    { 'certificate_generation_success', cert_file_path(),
      cert_priv_key_file_path() }
  | { 'certificate_generation_failure', error_reason() }.



-doc "Returned value once requesting a certificate.".
-type obtain_outcome() :: 'async' | obtained_outcome().




% Type shorthands:

-type count() :: basic_utils:count().
-type error_reason() :: basic_utils:error_reason().
-type tagged_error() :: basic_utils:tagged_error().

-type base_status() :: basic_utils:base_status().

-type ustring() :: text_utils:ustring().
-type bin_string() :: text_utils:bin_string().

-type file_name() :: file_utils: file_name().
-type bin_file_path() :: file_utils:bin_file_path().
-type any_file_path() :: file_utils:any_file_path().

-type any_directory_path() :: file_utils:any_directory_path().

-type milliseconds() :: unit_utils:milliseconds().

-type tcp_port() :: net_utils:tcp_port().

-type json() :: json_utils:json().

-type application_name() :: otp_utils:application_name().

-type bridge_spec() :: trace_bridge:bridge_spec().



%
% Public API: functions exported by this module in order to be directly called
% by the user.
%


-doc """
Returns an (ordered) list of the LEEC prerequisite OTP applications, to be
started in that order.

Notes:

- not listed here (not relevant for that use case): elli, getopt, yamerl,
erlang_color

- jsx preferred over jiffy; yet neither needs to be initialised as an
application

- no need to start Myriad either (library application)
""".
-spec get_ordered_prerequisites() -> [ application_name() ].
get_ordered_prerequisites() ->
    cond_utils:if_set_to( myriad_httpc_backend, shotgun,
                          [ shotgun ], _ThenNativeHttpc=[] ).



-doc """
Tells whether the specified atom is a known challenge type.

Does not guarantee that this LEEC instance is able to handle it.
""".
-spec is_known_challenge_type( atom() ) -> boolean().
is_known_challenge_type( _ChalType='http-01' ) ->
    true;

is_known_challenge_type( _ChalType='dns-01' ) ->
    true;

is_known_challenge_type( _ChalType ) ->
    false.



-doc """
Tells whether LEEC has a chance to run successfully a `dns-01` challenge.
""".
-spec can_perform_dns_challenges() -> boolean().
can_perform_dns_challenges() ->
    % Not a sufficient guarantee (and 'true' not returned):
    executable_utils:lookup_executable( "certbot" ) =/= false.



-doc """
Tells whether LEEC supports the specified DNS provider.

It is a necessary yet not sufficient condition (e.g. proper provider-specific
credentials will be needed as well).
""".
-spec is_supported_dns_provider( atom() ) -> boolean().
is_supported_dns_provider( _DNSProvider=ovh ) ->
    true;

is_supported_dns_provider( _DNSProvider ) ->
    false.



-doc """
Resets the LEEC state, typically prior to starting any (first) LEEC instance.

This may be useful for example with a certbot-based `dns-01` challenge, in order
to wipe out the state of certbot to ensure that new certificates are obtained
(as opposed to former ones being reused, whereas their expiration timestamp will
not be specifically read).

Otherwise tries to preserve state (e.g. any former certificate obtained through
http-01), as during the (potentially lengthy) renewal process, no functional
certificate (hence HTTPS access) would exist.

Returns whether a state deletion was done.

Not integrated to `start/{2,3}` as multiple LEEC instances can be used, and one
should not interfere with the others, through their common state (e.g. regarding
the one of certbot). Also, this may be useful only at the first LEEC
initialisation, not for the next automatic renewals.
""".
-spec reset_state( challenge_type(), any_directory_path() ) -> boolean().
reset_state( _ChallengeType='dns-01', AnyCertDir ) ->

    % Wipes out any previous certbot state tree, to force the recreation of
    % certificates (otherwise re-using preexisting ones may lead them to expire
    % before any renewal triggered through LEEC):

    % May be disabled for testing/troubleshooting; then a notification instead:
    %
    %trace_utils:warning( "Currently not wiping out certbot state "
    %   "to avoid the risk of exceeding the ACME certificate issuing "
    %   "maximum rate (5 over 168 hours for a given domain)." ),

    % Preferring not masking it:
    %cond_utils:if_defined( leec_debug_mode,
    trace_bridge:notice_fmt(
        "Resetting LEEC state, for the dns-01 challenge and "
        "the certificate directory '~ts'.", [ AnyCertDir ] ), % ),

    BinStateDir = file_utils:bin_join( AnyCertDir, ?certbot_state_dir ),

    % Enabled by default:
    file_utils:remove_directory_if_existing( BinStateDir ),

    % Hence existing, empty, with presumably adequate owner and permissions
    % (knowing that the internal directories created in ?certbot_state_dir by
    % certbot have proper, strict permissions - and certbot always checks them):
    %
    file_utils:create_directory_if_not_existing( BinStateDir ),

    true;

% Nothing to do, typically for http-01:
reset_state( _ChallengeType, _AnyCertDir ) ->
    false.



-doc """
Starts a linked, non-bridged instance of the LEEC service FSM, meant to rely on
the specified type of challenge.

See `start/3` for more details.
""".
-spec start( challenge_type(), [ start_option() ] ) -> start_outcome().
start( ChallengeType, StartOptions ) ->
    start( ChallengeType, StartOptions, _MaybeBridgeSpec=undefined ).



-doc """
Starts a linked instance of the LEEC service FSM, possibly with a trace bridge,
meant to rely on the specified type of challenge.

Note that for most challenges to succeed, LEEC must be started from the domain
of interest, as a webserver there must be controlled (for the `http-01`
challenge) or its DNS zone must be updated, generally from one of the authorised
IP addresses (for the `dns-01` challenge).

Note also that some challenges (especially the `dns-01` one) will take
significant time to succeed (typically as a few minutes will have to be waited
for DNS changes to propagate).
""".
-spec start( challenge_type(), [ start_option() ], option( bridge_spec() ) ) ->
                                        start_outcome().
% Apparently the 'application' behaviour would expect as argument:
% 'normal' | {'failover', atom()} | {'takeover', atom()}
% and, as return type:
% {'error', _} | {'ok', pid()} | {'ok', pid(), _} instead.
%
start( ChallengeType='http-01', StartOptions, MaybeBridgeSpec ) ->

    % If a trace bridge is specified, we use it both for the current (caller)
    % process and the ones it creates, i.e. the associated FSM and, possibly,
    % the helper process (if asynchronous operations are requested).

    % First this caller process:
    trace_bridge:register_if_not_already( MaybeBridgeSpec ),

    % shotgun not being listed in LEEC's .app file anymore (otherwise it would
    % be started even if native_httpc had been preferred), it is not
    % automatically started; this is thus done here (elli also is not wanted
    % anymore by default, it might be started only iff in standalone interfacing
    % mode):
    %
    % Intentionally no default token defined:
    cond_utils:switch_set_to( myriad_httpc_backend, [

        { shotgun,
            begin
                trace_bridge:info_fmt( "Starting LEEC (shotgun-based), "
                    "for the http-01 challenge with "
                    "following start options:~n  ~p.", [ StartOptions ] ),

                [ { ok, _Started } = application:ensure_all_started( A )
                    || A <- [ shotgun, elli ] ]
            end },

        { native_httpc,
            begin
                trace_bridge:info_fmt( "Starting LEEC (httpc-based), "
                    "for the http-01 challenge with "
                    "following start options:~n  ~p.", [ StartOptions ] ),

                web_utils:start( _Opt=ssl )
            end } ] ),

    JsonParserState = json_utils:start_parser(),

    { ok, _AppNames } = application:ensure_all_started( leec ),

    % Usually none, already started by framework (e.g. otp_utils):
    %trace_bridge:debug_fmt( "Applications started: ~p.", [ AppNames ] ),

    % Not registered in naming service on purpose, to allow for concurrent ACME
    % interactions (i.e. multiple, parallel instances).
    %
    % Calls init/1 on the new process, and returns its outcome:
    % (the FSM shall use any bridge as well)
    %
    { ok, FSMPid } = gen_statem:start_link( ?MODULE,
        _InitParams={ ChallengeType, StartOptions, JsonParserState,
                      MaybeBridgeSpec },
        _Opts=[] ),

    { ok, _LCS={ ChallengeType, FSMPid } };


start( ChallengeType='dns-01', StartOptions, MaybeBridgeSpec ) ->

    % First this caller process:
    trace_bridge:register_if_not_already( MaybeBridgeSpec ),

    trace_bridge:info_fmt( "Starting LEEC for the dns-01 challenge "
        "with following start options:~n  ~p.", [ StartOptions ] ),

    % Performing checks from the caller process is more convenient:

    BinCertbotPath = text_utils:string_to_binary(
        leec_bot:get_certbot_executable_path() ),

    BinCredBasePath = case list_table:lookup_entry( _K=cred_dir_path,
                                                    StartOptions ) of

        { value, CredBaseDir } ->
            file_utils:is_existing_directory_or_link( CredBaseDir ) orelse
                throw( { non_existing_credentials_directory, CredBaseDir } ),
            text_utils:ensure_binary( CredBaseDir );

        key_not_found ->
            throw( no_credentials_directory_set )

    end,

    BinWorkDir = case list_table:lookup_entry( work_dir_path, StartOptions ) of

        { value, WorkDir } ->
            file_utils:is_existing_directory_or_link( WorkDir ) orelse
                throw( { non_existing_work_directory, WorkDir } ),
            text_utils:ensure_binary( WorkDir );

        key_not_found ->
            file_utils:get_bin_current_directory()

    end,

    BinCertDir = case list_table:lookup_entry( cert_dir_path, StartOptions ) of

        { value, CertDir } ->
            file_utils:is_existing_directory_or_link( CertDir ) orelse
                throw( { non_existing_certificate_directory, CertDir } ),
            text_utils:ensure_binary( CertDir );

        key_not_found ->
            file_utils:get_bin_current_directory()

    end,

    % The place where certbot is to store its state:
    BinStateDir = file_utils:bin_join( BinCertDir, ?certbot_state_dir ),

    % As a result, any prior certbot state will be reused. We do not offer the
    % possibility of wiping it out here, as multiple (more or less concurrent)
    % LEEC instances may coexist, so none should not erase this common
    % state. Use reset_state/2 once, before any actual start of LEEC, if wanting
    % to start from scratch (which is recommended at least for the dns-01
    % challenge to properly expiration timestamps).

    LDState = #leec_dns_state{
        state_dir_path=BinStateDir,
        work_dir_path=BinWorkDir,
        certbot_path=BinCertbotPath,
        credentials_dir_path=BinCredBasePath,
        cert_dir_path=BinCertDir },

    trace_bridge:debug_fmt( "LEEC state: ~ts.",
                            [ state_to_string( LDState ) ] ),

    BotPid = ?myriad_spawn_link( _Mod=leec_bot, init_bot,
                                 [ LDState, MaybeBridgeSpec ] ),

    { ok, { ChallengeType, BotPid } };

start( ChallengeType, _StartOptions, _MaybeBridgeSpec ) ->
    { error, { unsupported_challenge_type, ChallengeType } }.



-doc """
Returns the default options for certificate requests for the specified challenge
type, here enabling the async (non-blocking) mode.
""".
-spec get_default_cert_request_options( challenge_type() ) ->
                                                cert_req_option_map().
get_default_cert_request_options( ChallengeType ) ->
    get_default_cert_request_options( ChallengeType, _Async=true ).



-doc """
Returns the default optionsfor certificate requests, with specified async mode.
""".
-spec get_default_cert_request_options( challenge_type(), boolean() ) ->
                                        cert_req_option_map().
get_default_cert_request_options( _ChallengeType='http-01', Async )
                                                when is_boolean( Async ) ->

    %trace_utils:debug( "Returning default certificate request options." ),

    #{ async => Async,
       netopts => #{ timeout => ?default_timeout,
                     % We check that we interact with the expected ACME server:
                     ssl => web_utils:get_ssl_verify_options( enable ) } };

get_default_cert_request_options( _ChallengeType='dns-01', Async )
                                                when is_boolean( Async ) ->

    %trace_utils:debug( "Returning default certificate request options." ),

    #{ async => Async }.



-doc """
Generates, once started, asynchronously (in a non-blocking manner), a new
certificate for the specified domain (FQDN).

Parameters:
- Domain is the domain name to generate an ACME certificate for
- LeecCallerState is the caller state obtained when starting LEEC

See `obtain_certificate_for/3` for the return type.

Belongs to the user-facing API; requires the LEEC service to be already started.
""".
-spec obtain_certificate_for( domain_name(), leec_caller_state() ) ->
                                        obtain_outcome().
obtain_certificate_for( Domain, LeecCallerState ) ->
    obtain_certificate_for( Domain, LeecCallerState, _NoCertReqOpts=#{} ).



-doc """
Generates, once started, synchronously (in a blocking manner) or not, a new
certificate for the specified domain (FQDN).

Parameters:
- Domain is the domain name to generate an ACME certificate for
- LeecCallerState is the caller state obtained when starting LEEC
- CertReqOptionMap is a map listing the options applying to this certificate
request, whose key (as atom) / value pairs may depend on the challenge type

Belongs to the user-facing API; requires the LEEC service to be already started.
""".
-spec obtain_certificate_for( Domain :: domain_name(), leec_caller_state(),
                              cert_req_option_map() ) -> obtain_outcome().
obtain_certificate_for( Domain,
        _LeecCallerState={ ChallengeType, FsmPid }, CertReqOptionMap )
                            when is_map( CertReqOptionMap ) ->

    BinDomain = text_utils:ensure_binary( Domain ),

    DefCertReqOpts = get_default_cert_request_options( ChallengeType ),

    % To ensure that all needed option entries are always defined:
    ReadyCertReqOptMap = maps:merge( DefCertReqOpts,
                                     _Prioritary=CertReqOptionMap ),

    % To trace any discrepancy in security options (like verify_peer):
    %
    %trace_bridge:warning_fmt( "The merge of the default certification request "
    %   "options ~p with the specified ones ~p resulted in:~n ~p.",
    %   "[ DefCertReqOpts, CertReqOptionMap, ReadyCertReqOptMap ] ),

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
                [ BinDomain, ChallengeType, FsmPid, ReadyCertReqOptMap,
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
            obtain_cert_helper( BinDomain, ChallengeType, FsmPid,
                                ReadyCertReqOptMap )

    end.



-doc """
Spawn helper, to be called either from a dedicated process or not, depending on
being async or not.
""".
-spec obtain_cert_helper( bin_domain(), challenge_type(), fsm_pid(),
                          cert_req_option_map() ) -> obtained_outcome().
obtain_cert_helper( BinDomain, _ChallengeType='http-01', FsmPid,
                    CertReqOptionMap=#{ async := Async,
                                        netopts := NetOpts } ) ->

    Timeout = maps:get( timeout, NetOpts, ?default_timeout ),

    ServerRef = FsmPid,

    % Expected to be in the 'idle' state, hence to trigger idle({create,
    % BinDomain, Opts}, _, LHState):
    %
    ObtainOutcome = case gen_statem:call( ServerRef,
            _Request={ create, BinDomain, CertReqOptionMap }, Timeout ) of

        % State of FSM shall thus be 'idle' now:
        ErrorTerm={ creation_failed, Error } ->
            trace_bridge:error_fmt( "Creation error reported by FSM ~w: ~p.",
                                    [ FsmPid, Error ] ),
            { certificate_generation_failure, ErrorTerm };

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

                    % With exponential backoff:
                    case wait_creation_completed( FsmPid, _Count=20 ) of

                        { certificate_ready, BinCertFilePath,
                          BinPrivKeyFilePath } ->
                            cond_utils:if_defined( leec_debug_fsm,
                                trace_bridge:debug_fmt( "Domain '~ts' "
                                    "finalized for ~w, returning certificate "
                                    "path '~ts' and its private key '~ts'.",
                                    [ BinDomain, FsmPid, BinCertFilePath,
                                      BinPrivKeyFilePath ] ) ),
                            { certificate_generation_success, BinCertFilePath,
                              BinPrivKeyFilePath };

                        Error ->
                            trace_bridge:error_fmt( "Error for FSM ~w when "
                                "finalizing domain '~ts': ~p.",
                                [ FsmPid, BinDomain, Error ] ),
                            { certificate_generation_failure, Error }

                    end;

                % Typically {error, timeout}:
                OtherError ->
                    cond_utils:if_defined( leec_debug_fsm,
                        trace_bridge:debug_fmt( "Reset of FSM ~w for '~ts' "
                            "after error ~p.",
                            [ FsmPid, BinDomain, OtherError ] ) ),
                    _ = gen_statem:call( _ServerRef=FsmPid, reset ),
                    { certificate_generation_failure, OtherError }

            end;

        Other ->
            trace_bridge:error_fmt( "Unexpected return after create for ~w: ~p",
                                    [ FsmPid, Other ] ),
            throw( { unexpected_create_return, Other, FsmPid } )

    end,

    Async andalso
        begin
            Callback = maps:get( callback, CertReqOptionMap,
                _DefaultCallback=fun( ObtOutcome ) ->
                    trace_bridge:warning_fmt( "Default async callback called "
                        "for ~w regarding http-01 creation outcome ~p.",
                        [ FsmPid, ObtOutcome ] )
                                 end ),

            %trace_bridge:debug_fmt( "Async callback called "
            %   "for ~w regarding creation outcome ~p.",
            %   [ FsmPid, CreationOutcome ] ),

            Callback( ObtainOutcome )

        end,

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "Obtain outcome for domain '~ts' (FSM: ~w): ~p",
        [ BinDomain, FsmPid, ObtainOutcome ] ) ),

    ObtainOutcome;


obtain_cert_helper( BinDomain, _ChallengeType='dns-01', FsmPid,
                    CertReqOptionMap=#{ async := Async } ) ->

    DNSProvider = case maps:find( _K=dns_provider, CertReqOptionMap ) of

        { ok, Provider } ->
            Provider;

        error ->
            trace_bridge:error_fmt( "No DNS provider set for domain '~ts'.",
                [ BinDomain ] ),
            throw( no_dns_provider_set )

    end,

    BinEmail = case maps:find( email, CertReqOptionMap ) of

        { ok, Email } ->
            text_utils:ensure_binary( Email );

        error ->
            text_utils:bin_format( "leec-certificates@~ts", [ BinDomain ] )

    end,


    % Not using gen_statem yet, just ad hoc messaging to the bot:
    case Async of

        true ->
            Callback = maps:get( callback, CertReqOptionMap,
                _DefaultCallback=fun( CreationOutcome ) ->
                    trace_bridge:warning_fmt(
                        "Default async callback called for domain '~ts' "
                        "regarding dns-01 creation outcome result ~p.",
                        [ BinDomain, CreationOutcome ] )
                                 end ),

            FsmPid ! { createCertificateAsync,
                       [ BinDomain, DNSProvider, BinEmail, Callback ] },
            async;

        false ->
            FsmPid ! { createCertificateSync,
                       [ BinDomain, DNSProvider, BinEmail ], self() },

            receive

                T={ certificate_generation_success, _BinCertFilePath,
                     _BinPrivKeyFilePath } ->
                    T;

                T={ certificate_generation_failure, _Error } ->
                    T

            end

    end.



-doc """
Spawn, bridged helper, to be called either from a dedicated process or not,
depending on being async or not.
""".
-spec obtain_cert_helper( domain_name(), challenge_type(), fsm_pid(),
            cert_req_option_map(), option( trace_bridge:bridge_info() ) ) ->
                obtained_outcome().
obtain_cert_helper( Domain, ChallengeType, FsmPid, CertReqOptionMap,
                    MaybeBridgeInfo ) ->

    % Let's inherit the creator bridge first:
    trace_bridge:set_bridge_info( MaybeBridgeInfo ),

    % And then branch to the main logic:
    obtain_cert_helper( Domain, ChallengeType, FsmPid, CertReqOptionMap ).



-doc """
Stops the specified instance of LEEC service; switches it to idle (does not
terminate it for good).
""".
-spec stop( leec_caller_state() ) -> void().
stop( _LCS={ _ChalType, FsmPid } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "Requesting FSM ~w to stop.", [ FsmPid ] ) ),

    % No more gen_fsm:sync_send_all_state_event/2 available, so
    % handle_call_for_all_states/4 will have to be called from all states
    % defined:
    %
    % (synchronous)
    %
    % As apparently may time-out:
    trace_bridge:warning_fmt( "Requesting FSM ~w to stop.", [ FsmPid ] ),
    Res = gen_statem:call( _ServerRef=FsmPid, _Request=stop, ?base_timeout ),
    trace_bridge:warning_fmt( "FSM ~w stopped.", [ FsmPid ] ),

    % Not stopped here, as stopping is only going back to the 'idle' state:
    %json_utils:stop_parser().

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "FSM ~w stopped (result: ~p).", [ FsmPid, Res ] ),
        basic_utils:ignore_unused( Res ) ).



-doc """
Terminates the specified instance of LEEC service: stops it properly, and
terminates the corresponding FSM process.

Not to be mixed up with the `terminate/3` function known as a gen_statem
callback.
""".
-spec terminate( leec_caller_state() ) -> void().
terminate( _LEECCallerState={ _ChalType='http-01', FsmPid } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "Requesting LEEC FSM ~w to terminate.", [ FsmPid ] ) ),

    % May exit the calling process with an exception 'timeout'
    % (e.g. {timeout,{gen_statem,call,[<0.676.0>,stop,15000]}}):
    %
    gen_statem:stop( FsmPid, _Reason=normal, _Timeout=5000 ),

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "LEEC FSM ~w terminated.", [ FsmPid ] ) );


terminate( _LEECCallerState={ _ChalType='dns-01', BotPid } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "Requesting LEEC bot ~w to terminate.", [ BotPid ] ) ),

    BotPid ! stop,

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "LEEC bot ~w (supposedly) terminated.", [ BotPid ] ) ).



%
% FSM internal API: callbacks triggered by gen_statem.
%


-doc """
Initialises the LEEC state machine.

Parameters:

- init TLS private key and its JWS

- fetch ACME directory

- get valid nonce

Will make use of any trace bridge transmitted.

Transitions to the `idle` initial state.
""".
-spec init( { challenge_type(), [ start_option() ], json_utils:parser_state(),
              option( bridge_spec() ) } ) ->
        { 'ok', InitialStateName :: 'idle', InitialData :: leec_http_state() }.
init( { ChallengeType, StartOptions, JsonParserState, MaybeBridgeSpec } ) ->

    % First action is to register this (unregistered by design) FSM to any
    % specified trace bridge:
    %
    trace_bridge:register( MaybeBridgeSpec ),

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "Initialising, with following options:~n  ~p.", [ StartOptions ] ) ),

    InitLHState = #leec_http_state{
        cert_req_option_map=get_default_cert_request_options( ChallengeType ),
        json_parser_state=JsonParserState,
        tcp_connection_cache=table:new() },

    LHState = setup_interfacing_mode(
        get_start_options( StartOptions, InitLHState ) ),

    % To check for example verify_peer:
    %trace_bridge:debug_fmt( "Initial LE state:~n ~p", [ LHState ] ),

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Initial state:~n  ~p", [ self(), LHState ] ) ),

    BinCertDirPath = LHState#leec_http_state.cert_dir_path,

    % Creates the private key pair of this LEEC agent, and initialises its JWS;
    % in case of parallel creations, ensuring automatically the uniqueness of
    % its filename is not trivial:
    %
    KeyFileInfo = case LHState#leec_http_state.agent_key_file_info of

        % If a key is to be created:
        undefined ->
            % We prefer here devising our own agent filename, lest its automatic
            % uniqueness is difficult to obtain (which is the case); we may use
            % in the future any user-specified identifier (see user_id field);
            % for now we stick to a simple approach based on the PID of this
            % LEEC FSM (no domain known yet):
            %
            %UniqFilename = text_utils:format(
            %  "leec-agent-private-~ts.key",
            %  [ LHState#leec_http_state.user_id ] ),

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

    AgentPrivateKey =
        leec_tls:obtain_private_key( KeyFileInfo, BinCertDirPath ),

    KeyJws = leec_jws:init( AgentPrivateKey ),

    OptionMap = LHState#leec_http_state.cert_req_option_map,

    % Directory map is akin to:
    %
    % #{<<"3TblEIQUCPk">> =>
    %     <<"ACME_COMM/t/adding-random-entries-to-the-directory/31417">>,
    %   <<"keyChange">> =>
    %     <<"ACME_BASE/acme/key-change">>,
    %   <<"meta">> =>
    %     #{<<"caaIdentities">> => [<<"letsencrypt.org">>],
    %       <<"termsOfService">> =>
    %   <<"https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf">>,
    %       <<"website">> =>
    %           <<"https://letsencrypt.org/docs/staging-environment/">>},
    %   <<"newAccount">> =>
    %     <<"ACME_BASE/acme/new-acct">>,
    %   <<"newNonce">> =>
    %     <<"ACME_BASE/acme/new-nonce">>,
    %   <<"newOrder">> =>
    %     <<"ACME_BASE/acme/new-order">>,
    %   <<"revokeCert">> =>
    %     <<"ACME_BASE/acme/revoke-cert">>}

    { URLDirectoryMap, DirLHState } = leec_api:get_directory_map(
        LHState#leec_http_state.environment, OptionMap, LHState ),

    { FirstNonce, NonceLHState } =
        leec_api:get_nonce( URLDirectoryMap, OptionMap, DirLHState ),

    cond_utils:if_defined( leec_debug_fsm,
        trace_bridge:debug_fmt( "[~w][state] Switching initially to 'idle'.",
                                [ self() ] ) ),

    % Next transition typically triggered by user code calling
    % obtain_certificate_for/{2,3}:
    %
    { ok, _NewStateName=idle,
      NonceLHState#leec_http_state{ directory_map=URLDirectoryMap,
                                    agent_private_key=AgentPrivateKey,
                                    jws=KeyJws,
                                    nonce=FirstNonce } }.



-doc """
Tells about the retained mode regarding callback. Here, one callback function
per state, akin to `gen_fsm`.
""".
-spec callback_mode() -> fsm_utils:callback_mode_ret().
callback_mode() ->
    % state_enter useful to trigger code once, when entering the 'finalize'
    % state for the first time:
    %
    [ state_functions, state_enter ].



-doc """
Returns the (absolute, binary) path of the current private key of the LEEC
agent.

Useful so that the same key can be used for multiple ACME orders (possibly in
parallel) rather than multiplying the keys.

(exported API helper)
""".
-spec get_agent_key_path( leec_caller_state() ) ->
            'error' | option( bin_file_path() ).
get_agent_key_path( _CallerState={ _ChalType, FsmPid } ) ->

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



-doc """
Returns the ongoing challenges with pre-computed thumbprints.

Returns `#{Challenge => Thumbrint}` if ok, `error` if fails.

(exported API helper)
""".
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



-doc """
Sends the ongoing challenges to the specified process.

Typically useful in a slave interfacing mode, when the web handler cannot access
directly the PID of the LEEC FSM: this code is then called by a third-party
process (e.g. a certificate manager one, statically known of the web handler,
and triggered by it), and returns the requested challenges to the specified
target PID (most probably the one of the web handler itself).

(exported API helper)
""".
-spec send_ongoing_challenges( leec_caller_state(), pid() ) -> void().
send_ongoing_challenges( _LCS={ _ChalType, FsmPid }, TargetPid ) ->
    % No error possibly reported:
    gen_statem:cast( _ServerRef=FsmPid,
                     _Msg={ send_ongoing_challenges, TargetPid } );

send_ongoing_challenges( InvalidLCS, TargetPid ) ->
    throw( { invalid_leec_caller_state, InvalidLCS, TargetPid } ).



% Section for gen_statem API, in the 'state_functions' callback mode: the
% branching is done depending on the current state name (as atom), so (like with
% gen_fsm) we proceed per-state, then, for a given state, we handle all possible
% events.
%
% An event is handled by the Module:StateName(EventType, EventContent, Data)
% function, which is to return either {next_state, NextState, NewData, Actions}
% or {next_state, NextState, NewData}.

% 4 states are defined in turn below:
% - idle (the initial state, after init/1)
% - pending
% - valid
% - finalize (hopefully the final state)



-doc """
Manages the `idle` state, the initial state, typically used when awaiting
for certificate requests to be triggered.
""".
% idle(get_ongoing_challenges | send_ongoing_challenges): nothing done
-spec idle( event_type(), event_content(), leec_http_state() ) ->
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
      _Data=LHState=#leec_http_state{ directory_map=DirMap,
                                      agent_private_key=AgentPrivKey,
                                      jws=Jws, nonce=Nonce } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] While idle: received a certificate creation "
        "request for domain '~ts', with following options:~n  ~p.",
        [ self(), BinDomain, CertReqOptionMap ] ) ),

    % For example 'http-01', 'tls-sni-01', etc.:
    ChallengeType = maps:get( challenge_type, CertReqOptionMap,
                              _DefaultChlgType='http-01' ),

    case ChallengeType of

        'http-01' ->
            ok;

        OtherChallengeType ->
            throw( { unsupported_challenge_type, OtherChallengeType } )

    end,

    { { AccountDecodedJsonMap, AccountLocationUri, AccountNonce },
      CreateLHState } = leec_api:get_acme_account( DirMap, AgentPrivKey,
        Jws#jws{ nonce=Nonce }, CertReqOptionMap, LHState ),

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
    AccountJws = #jws{ alg=Jws#jws.alg,
                       kid=AccountLocationUri,
                       nonce=AccountNonce },

    % Subject Alternative Names:
    Sans = maps:get( sans, CertReqOptionMap, _DefaultSans=[] ),

    BinSans = [ text_utils:ensure_binary( S ) || S <- Sans ],

    BinDomains = [ BinDomain | BinSans ],

    % Will transition to 'pending' to manage this request:
    { { OrderDecodedJsonMap, OrderLocationUri, OrderNonce }, ReqState } =
        leec_api:request_new_certificate( DirMap, BinDomains, AgentPrivKey,
            AccountJws, CertReqOptionMap, CreateLHState ),

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
    LocOrderMap = OrderDecodedJsonMap#{ <<"location">> => OrderLocationUri },

    AuthLHState = ReqState#leec_http_state{ domain=BinDomain, jws=AccountJws,
        account_key=AccountKey, nonce=OrderNonce, sans=BinSans },

    AuthUris = maps:get( <<"authorizations">>, OrderDecodedJsonMap ),

    { AuthPair, PerfLHState } =
        perform_authorization( ChallengeType, AuthUris, AuthLHState ),

    { NewStateName, Reply, NewUriChallengeMap, FinalNonce } =
            case AuthPair of

        { UriChallengeMap, AuthNonce } ->
            { pending, creation_pending, UriChallengeMap, AuthNonce }

        % Currently cannot happen:
        %{ error, Err, ErrAuthNonce } ->
        %   { idle, { creation_failed, Err }, _ResetChlgMap=#{}, ErrAuthNonce }

    end,

    FinalLHState = PerfLHState#leec_http_state{ nonce=FinalNonce,
                                                order=LocOrderMap,
                                                challenges=NewUriChallengeMap },

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w][state] Switching from 'idle' to '~ts'.",
        [ self(), NewStateName ] ) ),

    { next_state, NewStateName, _NewData=FinalLHState,
      _Action={ reply, From, Reply } };


idle( _EventType={ call, FromPid },
      _EventContentMsg=_Request=get_ongoing_challenges, _Data=_LHState ) ->

    trace_bridge:warning_fmt( "Received a get_ongoing_challenges request call "
        "from ~w while being idle.", [ FromPid ] ),

    % Clearer than {next_state, idle, LHState, {reply, FromPid,
    % _Reply=no_challenge}}:
    %
    { keep_state_and_data, { reply, FromPid, _Reply=no_challenge } };


idle( _EventType=cast,
      _EventContentMsg=_Request={ send_ongoing_challenges, TargetPid },
      _Data=_LHState ) ->

    % Should be pending:
    trace_bridge:warning_fmt( "Ignored a send_ongoing_challenges cast "
        "(targeting ~w) while being idle.", [ TargetPid ] ),

    keep_state_and_data;


% Possibly Request=stop:
idle( _EventType={ call, ServerRef }, _EventContentMsg=Request,
      _Data=LHState ) ->
    handle_call_for_all_states( ServerRef, Request, _StateName=idle, LHState );

idle( EventType, EventContentMsg, _LHState ) ->
    throw( { unexpected_event, EventType, EventContentMsg, { state, idle } } ).



-doc """
Manages the `pending` state, when challenges are on-the-go, that is being
processed with the ACME server.
""".
pending( _EventType=enter, _PreviousState, _Data ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Entering the 'pending' state.", [ self() ] ) ),

    keep_state_and_data;


% Returns a list of the currently ongoing challenges, with pre-computed
% thumbprints, i.e. a thumbprint_map().
%
pending( _EventType={ call, From }, _EventContentMsg=get_ongoing_challenges,
         _Data=LHState=#leec_http_state{ account_key=AccountKey,
                                         challenges=TypeChallengeMap } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Getting ongoing challenges.", [ self() ] ) ),

    % get_key_authorization/3 not returning a leec_http_state():
    ThumbprintMap = maps:from_list( [ { Token,
        _Thumbprint=leec_jws:get_key_authorization( AccountKey, Token,
                                                    LHState ) }
            || #{ <<"token">> := Token } <- maps:values( TypeChallengeMap ) ] ),

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Returning (get) from pending state challenge "
        "thumbprint map ~p.", [ self(), ThumbprintMap ] ) ),

    { next_state, _SameState=pending, LHState,
      _Action={ reply, From, _RetValue=ThumbprintMap } };


% Same as previous, except that the returned lessage is sent to target PID
% rather than to caller.
%
pending( _EventType=cast,
         _EventContentMsg={ send_ongoing_challenges, TargetPid },
         _Data=LHState=#leec_http_state{ account_key=AccountKey,
                                         challenges=TypeChallengeMap } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Ongoing challenges to be sent to ~w.", [ self(), TargetPid ] ) ),

    % get_key_authorization/3 not returning a leec_http_state():
    ThumbprintMap = maps:from_list( [ { Token,
        _Thumbprint=leec_jws:get_key_authorization( AccountKey, Token,
                                                    LHState ) }
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
%  - 'pending' if at least one challenge is not completed yet
%  - 'valid' if all challenges are complete
%
pending( _EventType={ call, From }, _EventContentMsg=check_challenges_completed,
         _Data=LHState=#leec_http_state{
            order=#{ <<"authorizations">> := AuthorizationsUris },
            nonce=InitialNonce,
            agent_private_key=PrivKey,
            jws=Jws,
            cert_req_option_map=CertReqOptionMap } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Checking whether challenges are completed.", [ self() ] ) ),

    % Checking the status for each authorization URI (one per host/SAN):
    { NextStateName, ResultingNonce, FoldLHState } = lists:foldl(

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
                % being able to fetch relevant challenges from local webserver:
                %
                { AnyState, <<"invalid">> } ->
                    trace_bridge:warning_fmt( "[~w] For auth URI ~ts, "
                        "switching from '~ts' to 'invalid' state.",
                        [ self(), AuthUri, AnyState ] ),
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
        _Acc0={ _InitialNextStateName=valid, InitialNonce, LHState },
        _List=AuthorizationsUris ),


    % Be nice to ACME server:
    case NextStateName of

        pending ->
            cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
                "[~w] Remaining in 'pending' state.", [ self() ] ) ),
            timer:sleep( 1000 );

        _ ->
            cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
                "[~w] Check resulted in switching from 'pending' to "
                "'~ts' state.", [ self(), NextStateName ] ), ok )

    end,

    { next_state, NextStateName,
      _NewData=FoldLHState#leec_http_state{ nonce=ResultingNonce },
      _Action={ reply, From, _RetValue=NextStateName } };


pending( _EventType={ call, From }, _EventContentMsg=Request=switchTofinalize,
         _Data=_LHState ) ->
    %cond_utils:if_defined( leec_debug_exchanges,
    trace_bridge:debug_fmt( "[~w] Received, while in 'pending' state, "
        "request '~ts' from ~w, currently ignored.",
        [ self(), Request, From ] ),

    % { next_state, finalize, ...}?

    keep_state_and_data;


pending( _EventType={ call, ServerRef }, _EventContentMsg=Request,
         _Data=LHState ) ->
    handle_call_for_all_states( ServerRef, Request, _StateName=pending,
                                LHState );

pending( EventType, EventContentMsg, _LHState ) ->
    trace_bridge:warning_fmt( "[~w] Received, while in 'pending' state, "
        "event type '~p' and content message '~p'.",
        [ self(), EventType, EventContentMsg ] ),

    throw( { unexpected_event, EventType, EventContentMsg,
                { state, pending } } ).



-doc """
Manages the `valid` state.

When challenges have been successfully completed, finalizes the ACME order and
generates the TLS certificate.

Returns Status, the order status.

Transitions to the `finalize` state.
""".
valid( _EventType=enter, _PreviousState, _Data ) ->
    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Entering the 'valid' state.", [ self() ] ) ),
    keep_state_and_data;

valid( _EventType={ call, _ServerRef=From },
       _EventContentMsg=_Request=switchTofinalize,
       _Data=LHState=#leec_http_state{
            interfacing_mode=InterfMode,
            domain=BinDomain,
            sans=SANs,
            cert_dir_path=BinCertDirPath,
            order=OrderDirMap,
            agent_private_key=AgentPrivKey,
            jws=Jws,
            nonce=Nonce,
            cert_req_option_map=CertReqOptionMap } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Trying to switch to finalize while being in the 'valid' state.",
        [ self() ] ) ),

    DestroyLHState = challenge_destroy( InterfMode, LHState ),

    CertPrivKeyFilename = get_certificate_priv_key_filename( BinDomain ),

    % To avoid a warning:
    file_utils:remove_file_if_existing(
        file_utils:join( BinCertDirPath, CertPrivKeyFilename ) ),

    % KeyFilePath is required for CSR generation:
    CreatedTLSPrivKey = leec_tls:obtain_private_key(
        { new, CertPrivKeyFilename }, BinCertDirPath ),

    BinCertPrivKeyFilePath = CreatedTLSPrivKey#tls_private_key.file_path,

    cond_utils:if_defined( leec_debug_fsm,
        basic_utils:assert_equal( BinCertPrivKeyFilePath,
            file_utils:bin_join( BinCertDirPath, CertPrivKeyFilename ) ) ),

    Csr = leec_tls:get_cert_request( BinDomain, BinCertDirPath, SANs ),

    { { FinOrderDirMap, _BinLocUri, FinNonce }, FinLHState } =
        leec_api:finalize_order( OrderDirMap, Csr, AgentPrivKey,
            Jws#jws{ nonce=Nonce }, CertReqOptionMap, DestroyLHState ),

    BinStatus = maps:get( <<"status">>, FinOrderDirMap ),

    % Expected to be 'finalize' sooner or later:
    ReadStateName = leec_api:binary_to_status( BinStatus ),

    % Puts back 'location' in finalized order:
    LocOrderDirMap = FinOrderDirMap#{
        <<"location">> => maps:get( <<"location">>, OrderDirMap ) },

    LastLHState = FinLHState#leec_http_state{
        order=LocOrderDirMap,
        cert_priv_key_path=BinCertPrivKeyFilePath,
        nonce=FinNonce },

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w][state] Switching from 'valid' to 'finalize' "
        "(after having read '~ts').", [ self(), ReadStateName ] ) ),

    { next_state, _NewStateName=finalize, _NewData=LastLHState,
      _Action={ reply, From, _Reply=ReadStateName } };


valid( _EventType={ call, ServerRef }, _EventContentMsg=Request,
       _Data=LHState ) ->
    handle_call_for_all_states( ServerRef, Request, _StateName=valid,
                                LHState );

valid( EventType, EventContentMsg, _LHState ) ->
    throw( { unexpected_event, EventType, EventContentMsg,
            { state, valid }, self() } ).



-doc """
Manages the `finalize` state.

When order is being finalized, and certificate generation is ongoing.

Waits for certificate generation being complete (order status becoming `valid`).

Returns the order status.

Transitions to:
  state `processing`: still ongoing
  state `valid`     : certificate is ready
""".
finalize( _EventType=enter, _PreviousState, _Data ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Entering the 'finalize' state.", [ self() ] ) ),

    keep_state_and_data;

finalize( _EventType={ call, _ServerRef=From },
          _EventContentMsg=_Request=manageCreation,
          _Data=LHState=#leec_http_state{
                order=OrderMap,
                domain=BinDomain,
                cert_dir_path=BinCertDirPath,
                cert_priv_key_path=BinCertPrivKeyPath,
                agent_private_key=AgentPrivKey, jws=Jws, nonce=Nonce,
                cert_req_option_map=CertReqOptionMap } ) ->

    cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
        "[~w] Getting progress of creation procedure "
        "based on order map:~n   ~p.", [ self(), OrderMap ] ) ),

    %trace_bridge:debug_fmt( "[~w] Getting progress of creation procedure "
    %                        "based on order map.", [ self() ] ),

    trace_utils:warning_fmt( "Order map from finalize: ~n  ~p", [ OrderMap ] ),

    % Apparently some rare error cases used to lead to this key not existing,
    % most probably because the next returned NewOrderMap did not have this
    % 'location' key anymore before iterating on it again, knowing this request
    % is polled by the waiting client (now this key is put back):
    %
    Loc = maps:get( <<"location">>, OrderMap ),

    { { NewOrderMap, _NullLoc, OrderNonce }, OrderState } =
        leec_api:get_order( Loc, AgentPrivKey, Jws#jws{ nonce=Nonce },
                            CertReqOptionMap, LHState ),

    % So now we put back the location (see previous comment):
    LocNewOrderMap = NewOrderMap#{ <<"location">> => Loc },

    BinStatus = maps:get( <<"status">>, LocNewOrderMap ),

    ReadStatus = leec_api:binary_to_status( BinStatus ),

    { { Reply, NewStateName, NewNonce, NewJws }, ReadLHState } =
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

            % Downloads the actual, final certificate:
            { { BinCert, DownloadNonce }, CertLHState } =
                leec_api:get_certificate( OrderMap, AgentPrivKey,
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
            % No, and the current JWS would not be suitable for that (e.g. not
            % having the public key of that LEEC agent), and anyway we prefer
            % creating a new account each time a new operation is performed (as
            % ~90 days may elapse between two operations). So:
            %
            AgentKeyJws = leec_jws:init( AgentPrivKey ),

            % Safer, not wasting idle connections, bound to fail after some time
            % anyway:
            %
            leec_api:close_tcp_connections(
                OrderState#leec_http_state.tcp_connection_cache ),

            CloseLHState = CertLHState#leec_http_state{
                tcp_connection_cache=table:new() },

            Result = { certificate_ready, BinCertFilePath, BinCertPrivKeyPath },

            { { Result, idle, DownloadNonce, AgentKeyJws }, CloseLHState };


        % Like for 'processing', yet with a different trace:
        OtherStatus ->
            trace_bridge:warning_fmt( "[~w] Unexpected read status while "
                "finalizing: '~ts' (ignored).", [ self(), OtherStatus ] ),
            { { creation_in_progress, finalize, OrderNonce, Jws }, OrderState }

    end,

    FinalLHState = ReadLHState#leec_http_state{ order=LocNewOrderMap,
                                                jws=NewJws,
                                                nonce=NewNonce },

    { next_state, NewStateName, _NewData=FinalLHState,
      _Action={ reply, From, Reply } };


finalize( _EventType={ call, ServerRef }, _EventContentMsg=Request,
          _Data=LHState ) ->
    handle_call_for_all_states( ServerRef, Request, _StateName=finalize,
                                LHState );


finalize( UnexpectedEventType, EventContentMsg, _LHState ) ->

    trace_bridge:error_fmt( "Unknown event ~p (content: ~p) in "
        "finalize status.", [ UnexpectedEventType, EventContentMsg ] ),

    %{ reply, { error, UnexpectedEventType }, finalize, LHState }.

    throw( { unexpected_event, UnexpectedEventType, EventContentMsg,
                { state, finalize } } ).



-doc """
Manages the `invalid` state.

When order is being finalized, and certificate generation is ongoing.

Waits for certificate generation being complete (order status == `valid`).

Returns the order status.

Transitions to:
  state `processing`: still ongoing
  state `valid`     : certificate is ready
""".
invalid( _EventType=enter, _PreviousState, _Data=LHState ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Entering the 'invalid' state.", [ self() ] ) ),

    trace_bridge:error_fmt( "[~w] Reached the (stable) 'invalid' state for "
        "domain '~ts'. The ACME server must not have found a suitable "
        "answer to its challenge.",
        [ self(), LHState#leec_http_state.domain ] ),

    keep_state_and_data.




% Callback section.


-doc "Handles the specified call in the same way for all states.".
-spec handle_call_for_all_states( server_ref(), request(), state_name(),
        leec_http_state() ) -> state_callback_result().
handle_call_for_all_states( ServerRef, _Request=get_status, StateName,
                            _LHState ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Returning current status: '~ts'.", [ ServerRef, StateName ] ) ),

    Res = StateName,

    { keep_state_and_data, _Actions={ reply, _From=ServerRef, Res } };


handle_call_for_all_states( ServerRef, _Request=get_agent_key_path, StateName,
                            LHState ) ->

    MaybeAgentKeyPath = case LHState#leec_http_state.agent_private_key of

        undefined ->
            undefined;

        PrivKey ->
            PrivKey#tls_private_key.file_path

    end,

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Returning agent key path (while in state '~ts'): ~p.",
        [ ServerRef, StateName, MaybeAgentKeyPath ] ),
        basic_utils:ignore_unused( StateName ) ),

    { keep_state_and_data, _Actions={ reply, _From=ServerRef,
                                      _Res=MaybeAgentKeyPath } };


handle_call_for_all_states( ServerRef, _Request=stop, StateName,
        LHState=#leec_http_state{ interfacing_mode=InterfMode } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Received a stop request from ~ts state.",
        [ ServerRef, StateName ] ),
        basic_utils:ignore_unused( [ ServerRef, StateName ] ) ),

    trace_bridge:warning_fmt(
        "FSM ~w is to stop, while in interfacing mode '~p'.",
        [ self(), InterfMode ] ),

    DestroyLHState = challenge_destroy( InterfMode, LHState ),

    % Stopping is just returning back to idle (no action):

    %{ stop_and_reply, _Reason, _Reply={ reply, ServerRef, ok },
    %   _Data=LHState }.

    trace_bridge:warning_fmt( "FSM ~w stopped, switching to idle'.",
                              [ self() ] ),
    { next_state, _NextState=idle, _NewData=DestroyLHState };


handle_call_for_all_states( ServerRef, Request, StateName, _LHState ) ->

    trace_bridge:error_fmt( "[~w] Received an unexpected request, ~p, "
        "while in state ~p.", [ ServerRef, Request, StateName ] ),

    throw( { unexpected_request, Request, ServerRef, StateName } ).




% Standard gen_statem callbacks:


-doc "Standard termination callback.".
terminate( Reason, State, Data ) ->
    trace_bridge:warning_fmt( "FSM ~w terminating "
        "(reason: ~p state: ~p; data: ~p).",
        [ self(), Reason, State, Data ] ).



-doc """
Standard "code change" callback.
""".
code_change( _, StateName, LHState, _ ) ->
    trace_bridge:warning_fmt( "FSM ~w changing code.", [ self() ] ),
    { ok, StateName, LHState }.




% Helpers.


-doc """
Parses the `start/1` options.

Available options are:

- environment: to run against a production or staging ACME environment

- interfacing_mode: webroot, slave or standalone

- agent_key_file_path: to reuse an existing agent TLS key

- cert_dir_path: path to read/save TLS certificates, keys and CSR requests

- webroot_dir_path: the webroot directory, in a conventional subdirectory of
which challenge answers shall be written so that the ACME server can download
them

- port: the TCP port at which the corresponding webserver shall be available, in
standalone interfacing mode

- http_timeout: timeout for ACME API requests (in milliseconds)

Returns LHState (type record `leec_http_state`) filled with corresponding,
checked option values.
""".
-spec get_start_options( [ start_option() ], leec_http_state() ) ->
                                leec_http_state().
get_start_options( _Opts=[], LHState ) ->
    LHState;

get_start_options( _Opts=[ { environment, Env } | T ], LHState ) ->

    lists:member( Env, [ staging, production ] ) orelse
        throw( { invalid_environment, Env } ),

    get_start_options( T, LHState#leec_http_state{ environment=Env } );

get_start_options( _Opts=[ { interfacing_mode, InterfMode } | T ], LHState ) ->
    lists:member( InterfMode, [ webroot, slave, standalone ] ) orelse
        throw( { invalid_leec_interfacing_mode, InterfMode } ),
    get_start_options( T,
                       LHState#leec_http_state{ interfacing_mode=InterfMode } );

% To re-use a previously-stored agent private key:
get_start_options( _Opts=[ { agent_key_file_path, KeyFilePath } | T ],
                   LHState ) ->

    AgentKeyFilePath = text_utils:ensure_string( KeyFilePath ),

    % Not knowin the certificate directory yet, so checking only if absolute:
    case file_utils:is_absolute_path( AgentKeyFilePath ) of

        true ->
            case file_utils:is_existing_file_or_link( AgentKeyFilePath ) of

                true ->
                    case file_utils:is_user_readable( AgentKeyFilePath ) of

                        true ->
                            BinAgentKeyFilePath =
                                text_utils:string_to_binary( AgentKeyFilePath ),

                            get_start_options( T, LHState#leec_http_state{
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
                LHState#leec_http_state{ agent_key_file_info=
                    text_utils:string_to_binary( AgentKeyFilePath ) } )

    end;


get_start_options( _Opts=[ { cert_dir_path, BinCertDirPath } | T ], LHState )
                                when is_binary( BinCertDirPath ) ->
    case file_utils:is_existing_directory_or_link( BinCertDirPath ) of

        true ->
            get_start_options( T,
                LHState#leec_http_state{ cert_dir_path=BinCertDirPath } );

        false ->
            throw( { non_existing_certificate_directory,
                     text_utils:binary_to_string( BinCertDirPath ) } )

    end;

get_start_options( _Opts=[ { cert_dir_path, CertDirPath } | T ], LHState ) ->
    BinCertDirPath = text_utils:string_to_binary( CertDirPath ),
    get_start_options( [ { cert_dir_path, BinCertDirPath } | T ], LHState );


get_start_options( _Opts=[ { webroot_dir_path, BinWebDirPath } | T ], LHState )
                                when is_binary( BinWebDirPath ) ->
    case file_utils:is_existing_directory_or_link( BinWebDirPath ) of

        true ->
            get_start_options( T,
                LHState#leec_http_state{ webroot_dir_path=BinWebDirPath } );

        false ->
            throw( { non_existing_webroot_directory,
                     text_utils:binary_to_string( BinWebDirPath ) } )

    end;

get_start_options( _Opts=[ { webroot_dir_path, WebDirPath } | T ], LHState ) ->
    BinWebDirPath = text_utils:ensure_binary( WebDirPath ),
    get_start_options( [ { webroot_dir_path, BinWebDirPath } | T ], LHState );


get_start_options( _Opts=[ { port, Port } | T ], LHState )
  when is_integer( Port ) ->
    get_start_options( T, LHState#leec_http_state{ port=Port } );

get_start_options( _Opts=[ { port, Port } | _T ], _LHState ) ->
    throw( { invalid_standalone_tcp_port, Port } );

get_start_options( _Opts=[ { http_timeout, Timeout } | T ], LHState )
  when is_integer( Timeout ) ->
    CertReqOptMap = LHState#leec_http_state.cert_req_option_map,
    NetOpts = maps:get( netopts, CertReqOptMap, _DefNetOpts=#{} ),
    % Supersedes any prior value:
    NetOptsWithTimeout = NetOpts#{ timeout => Timeout },
    NewCertReqOptMap = CertReqOptMap#{ netopts => NetOptsWithTimeout },

    get_start_options( T, LHState#leec_http_state{
                                cert_req_option_map=NewCertReqOptMap } );

get_start_options( _Opts=[ { http_timeout, Timeout } | _T ], _LHState ) ->
    throw( { invalid_http_timeout, Timeout } );

get_start_options( _Opts=[ Unexpected | _T ], _LHState ) ->
    trace_bridge:error_fmt( "Invalid LEEC option specified: ~p.",
                            [ Unexpected ] ),
    throw( { invalid_leec_option, Unexpected } ).



-doc "Setups the context of the chosen interfacing mode.".
-spec setup_interfacing_mode( leec_http_state() ) -> leec_http_state().
setup_interfacing_mode( #leec_http_state{ interfacing_mode=webroot,
                                          webroot_dir_path=undefined } ) ->
    trace_bridge:error( "Missing 'webroot_dir_path' parameter." ),
    throw( webroot_dir_path_missing );

setup_interfacing_mode( LHState=#leec_http_state{
                            interfacing_mode=webroot,
                            webroot_dir_path=BinWebrootPath } ) ->

    ChallengeDirPath =
        file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

    % TODO: check that directory is writable.
    file_utils:create_directory_if_not_existing( ChallengeDirPath,
                                                 create_parents ),

    LHState;

% Already checked:
setup_interfacing_mode( LHState=#leec_http_state{
        interfacing_mode=standalone, port=Port } ) when is_integer( Port ) ->
    % TODO: check port is unused?
    LHState;

setup_interfacing_mode( LHState=#leec_http_state{ interfacing_mode=slave } ) ->
    LHState;

% Every other mode value is invalid:
setup_interfacing_mode( #leec_http_state{ interfacing_mode=undefined } ) ->

    trace_bridge:error( "Interfacing mode not set "
                        "(see the 'interfacing_mode' start option)." ),

    throw( interfacing_mode_not_set );

setup_interfacing_mode( #leec_http_state{ interfacing_mode=InterfMode } ) ->
    trace_bridge:error_fmt( "Invalid '~p' interfacing mode.", [ InterfMode ] ),
    throw( { invalid_interfacing_mode, InterfMode } ).



-doc """
Loops a few times on authorization check until challenges are all validated
(with increasing waiting times after each attempt); if successful, the FSM
should be in `valid` state when returning.

Returns:
- `{error, timeout}` if failed after X loops
- `{error, Err}` if another error
- `ok` if succeed
""".
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



-doc "As returned by a FSM.".
-type wait_creation_result() ::
    { 'certificate_ready', bin_file_path(), bin_file_path() }
  | { 'error', 'timeout' }.



-doc "Waits until the certification creation is reported as completed.".
-spec wait_creation_completed( fsm_pid(), count() ) -> wait_creation_result().
wait_creation_completed( FsmPid, C ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Waiting for the completion of the "
        "certificate creation...", [ FsmPid ] ) ),

    wait_creation_completed( FsmPid, C, C ).



-doc "Waits until specified status is read.".
-spec wait_creation_completed( fsm_pid(), count(), count() ) ->
                                wait_creation_result().
wait_creation_completed( _FsmPid, _Count=0, _Max ) ->
    { error, timeout };

wait_creation_completed( FsmPid, Count, Max ) ->

    case gen_statem:call( _ServerRef=FsmPid, _Req=manageCreation,
                          ?base_timeout ) of

        Reply={ certificate_ready, BinCertFilePath, BinCertPrivKeyPath } ->
            cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
                "End of waiting for creation of certificate '~ts' "
                "(whose private key is '~ts'): read target status "
                "'finalize' for ~w.",
                [ BinCertFilePath, BinCertPrivKeyPath, FsmPid ] ),
                basic_utils:ignore_unused(
                    [ BinCertFilePath, BinCertPrivKeyPath ] ) ),
            Reply;

        creation_in_progress ->
            cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
                "Still waiting for creation from ~w.", [ FsmPid ] ) ),
            % Thus each time waiting for half a second more:
            timer:sleep( 500 * ( Max - Count + 1 ) ),
            wait_creation_completed( FsmPid, Count-1, Max );

        % Not expected to ever happen:
        Any ->
            trace_bridge:warning_fmt( "Received unexpected '~p' for ~w while "
                "waiting for creation (ignored).", [ Any, FsmPid ] ),
            wait_creation_completed( FsmPid, Count-1, Max )

    end.



-doc "Performs ACME authorization based on selected challenge initialization.".
-spec perform_authorization( challenge_type(), [ bin_uri() ],
                             leec_http_state() ) ->
        { { uri_challenge_map(), nonce() }, leec_http_state() }.
perform_authorization( ChallengeType, AuthUris,
        LHState=#leec_http_state{ interfacing_mode=InterfMode } ) ->

    cond_utils:if_defined( leec_debug_fsm, trace_bridge:debug_fmt(
        "[~w] Starting authorization procedure with "
        "challenge type '~ts' (interfacing mode: ~ts).",
        [ self(), ChallengeType, InterfMode ] ) ),

    BinChallengeType = text_utils:atom_to_binary( ChallengeType ),

    { { UriChallengeMap, Nonce }, FirstLHState } = perform_authorization_step1(
        AuthUris, BinChallengeType, LHState, _UriChallengeMap=#{} ),

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

    init_for_challenge_type( ChallengeType, InterfMode, FirstLHState,
                             UriChallengeMap ),

    { NewNonce, SecondLHState } = perform_authorization_step2(
        maps:to_list( UriChallengeMap ),
        FirstLHState#leec_http_state{ nonce=Nonce } ),

    { { UriChallengeMap, NewNonce }, SecondLHState }.



-doc """
Requests authorizations based on specified challenge type and URIs: for each
challenge type (e.g. `http-01`, `dns-01`, etc.), a challenge is proposed.

At least in some cases, a single authorization URI is actually listed.

Returns `{ok, Challenges, Nonce}` where:

- Challenges is map of Uri -> Challenge, where Challenge is of ChallengeType
   type

- Nonce is a new valid replay-nonce
""".
-spec perform_authorization_step1( [ bin_uri() ], bin_challenge_type(),
        leec_http_state(), uri_challenge_map() ) ->
            { { uri_challenge_map(), nonce() }, leec_http_state() }.
perform_authorization_step1( _AuthUris=[], _BinChallengeType,
        LHState=#leec_http_state{ nonce=Nonce }, UriChallengeMap ) ->
    { { UriChallengeMap, Nonce }, LHState };

perform_authorization_step1( _AuthUris=[ AuthUri | T ], BinChallengeType,
            LHState=#leec_http_state{ nonce=Nonce,
                agent_private_key=AgentPrivKey,
                jws=Jws, cert_req_option_map=CertReqOptionMap },
            UriChallengeMap ) ->

    % For example AuthUri = "ACME_BASE/acme/authz-v3/133572032"

    { { AuthMap, _LocUri, NewNonce }, ReqLHState } =
        leec_api:request_authorization( AuthUri, AgentPrivKey,
            Jws#jws{ nonce=Nonce }, CertReqOptionMap, LHState ),

    cond_utils:if_defined( leec_debug_exchanges, trace_bridge:debug_fmt(
        "[~w] Step 1: authmap returned for URI '~ts':~n  ~p.",
        [ self(), AuthUri, AuthMap ] ) ),

    % For example AuthMap =
    % #{<<"challenges">> =>
    %      [#{<<"status">> => <<"pending">>,
    %         <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
    %         <<"type">> => <<"http-01">>,
    %         <<"url">> =>
    % <<"ACME_BASE/acme/chall-v3/133572032/Zu9ioQ">>},
    %       #{<<"status">> => <<"pending">>,
    %         <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
    %         <<"type">> => <<"dns-01">>,
    %         <<"url">> =>
    % <<"ACME_BASE/acme/chall-v3/133572032/u9WbrQ">>},
    %       #{<<"status">> => <<"pending">>,
    %         <<"token">> => <<"Nvkad5EmNiANy5-8oPvJ_a29A-iGcCS4aR3MynPc9nM">>,
    %         <<"type">> => <<"tls-alpn-01">>,
    %         <<"url">> =>
    % <<"ACME_BASE/acme/chall-v3/133572032/_WS56A">>}],
    %   <<"expires">> => <<"2020-10-18T14:48:11Z">>,
    %   <<"identifier">> =>
    %      #{<<"type">> => <<"dns">>,<<"value">> => <<"www.foobar.org">>},
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
        ReqLHState#leec_http_state{ nonce=NewNonce },
        UriChallengeMap#{ AuthUri => Challenge } ).



-doc """
Second step of the authorization process, executed after challenge
initialization.

Notifies the ACME server the challenges are good to proceed, returns an updated
nonce.
""".
-spec perform_authorization_step2( [ { bin_uri(), challenge() } ],
                leec_http_state()) -> { nonce(), leec_http_state() }.
perform_authorization_step2( _Pairs=[],
                             LHState=#leec_http_state{ nonce=Nonce } ) ->
    { Nonce, LHState };

perform_authorization_step2( _Pairs=[ { Uri, Challenge } | T ],
        LHState=#leec_http_state{ nonce=Nonce, agent_private_key=AgentPrivKey,
            jws=Jws, cert_req_option_map=CertReqOptionMap } ) ->

    { { Resp, _Location, NewNonce }, NotifLHState } =
        leec_api:notify_ready_for_challenge( Challenge, AgentPrivKey,
            Jws#jws{ nonce=Nonce }, CertReqOptionMap, LHState ),

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

    perform_authorization_step2( T,
        NotifLHState#leec_http_state{ nonce=NewNonce } ).



-doc """
Initializes the local configuration to serve the specified challenge type.

Depends on challenge type and interfacing mode.
""".
-spec init_for_challenge_type( challenge_type(), web_interfacing_mode(),
        leec_http_state(), uri_challenge_map() ) -> void().
% Here we directly write challenges in a web root that is already being served
% through other means:
%
init_for_challenge_type( _ChallengeType='http-01', _InterfMode=webroot,
        LHState=#leec_http_state{ webroot_dir_path=BinWebrootPath,
                                  account_key=AccountKey },
        UriChallengeMap ) ->

    [ begin

        ChlgWebDir = file_utils:join( BinWebrootPath, ?webroot_challenge_path ),

        file_utils:create_directory_if_not_existing( ChlgWebDir ),

        ChlgWebPath = file_utils:join( ChlgWebDir, Token ),

        Thumbprint = leec_jws:get_key_authorization( AccountKey, Token,
                                                     LHState ),

        % The default modes are fine:
        file_utils:write_whole( ChlgWebPath, Thumbprint )

      end || #{ <<"token">> := Token } <- maps:values( UriChallengeMap ) ];


% Here we never write challenges, we trigger the user-specified callback
% whenever challenges are ready:
%
init_for_challenge_type( _ChallengeType, _InterfMode=slave, _LHState,
                         _UriChallengeMap ) ->
    ok;


% Here we spawn a dedicated (elli-based) webserver in order to host the
% challenges to be downloaded by the ACME server:
%
init_for_challenge_type( ChallengeType, _InterfMode=standalone,
        LHState=#leec_http_state{ port=Port,
                                  domain=Domain,
                                  account_key=AccntKey },
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
                                                           Token, LHState ) }
                        || #{ <<"token">> := Token }
                                <- maps:values( UriChallengeMap ) ] ),

            { ok, _ } = elli:start_link([
                { name, { local, leec_elli_listener } },
                { callback, leec_elli_handler },
                { callback_args, [ #{ Domain => Thumbprints } ] },
                % If is not 80, a priori should not work as ACME to look for it:
                { port, Port } ] )

        %'tls-sni-01' ->
        %   TODO

        % Cannot happen:
        %_ ->
        %   trace_bridge:error_fmt( "Standalone mode: unsupported ~p challenge "
        %                           "type.", [ ChallengeType ] ),
        %
        %   throw( { unsupported_challenge_type, ChallengeType, standalone } )

    end.



-doc """
Cleans up challenge context after it has been fullfilled (with success or not).

In:
- `webroot` mode: delete token file
- `standalone` mode: stop internal webserver
- `slave` mode: nothing to do
""".
-spec challenge_destroy( web_interfacing_mode(), leec_http_state() ) ->
                                    leec_http_state().
challenge_destroy( _InterfMode=webroot,
                   LHState=#leec_http_state{ webroot_dir_path=BinWPath,
                                             challenges=UriChallengeMap } ) ->

    [ begin

        ChalWebPath =
            file_utils:join( [ BinWPath, ?webroot_challenge_path, Token ] ),

        file_utils:remove_file( ChalWebPath )

      end || #{ <<"token">> := Token } <- maps:values( UriChallengeMap ) ],

    LHState#leec_http_state{ challenges=#{} };


challenge_destroy( _InterfMode=standalone, LHState ) ->
    % Stop http server:
    elli:stop( leec_elli_listener ),
    LHState#leec_http_state{ challenges=#{} };


challenge_destroy( _InterfMode=slave, LHState ) ->
    LHState#leec_http_state{ challenges=#{} }.




% Section specific to the dns-01 challenge.


-doc "Returns a textual representation of the specified DNS provider.".
-spec dns_provider_to_string( dns_provider() ) -> ustring().
dns_provider_to_string( _DNSProvider=ovh ) ->
    "ovh";

dns_provider_to_string( DNSProvider ) ->
    throw( { unsupported_dns_provider, DNSProvider } ).



-doc """
Returns a file path corresponding to the specified domain name managed by the
specified DNS provider, in the specified credentials directory, made based on
the proposed LEEC conventions.
""".
-spec get_credentials_path_for( dns_provider(), domain_name(),
                                any_directory_path() ) -> credentials_path().
get_credentials_path_for( DNSProvider, DomainName, AnyCredBasePath ) ->

    Filename = text_utils:format( "leec-~ts-credentials-for-~ts.txt",
        [ dns_provider_to_string( DNSProvider ), DomainName ] ),

    file_utils:ensure_path_is_absolute(
        file_utils:bin_join( AnyCredBasePath, Filename ) ).



-doc """
Returns the filename of the private key of the certificate for the specified
domain.
""".
-spec get_certificate_priv_key_filename( domain_name() ) -> file_name().
get_certificate_priv_key_filename( DomainName ) ->
    text_utils:format( "~ts.key", [ DomainName ] ).



-doc "Returns a textual description of the specified LEEC (internal) state.".
-spec state_to_string( leec_state() ) -> ustring().
state_to_string( LHS=#leec_http_state{} ) ->
    text_utils:format( "LEEC http state: ~p", [ LHS ]);

state_to_string( LDS=#leec_dns_state{ certbot_path=CertbotPath } ) ->
    text_utils:format( "LEEC dns state, using executable '~ts': ~p",
                       [ CertbotPath, LDS ] ).



-doc "Returns a textual description of the specified LEEC caller state.".
-spec caller_state_to_string( leec_caller_state() ) -> ustring().
caller_state_to_string( _LEECCallerState={ ChalType, LeecFsmPid } ) ->
    text_utils:format( "LEEC caller state of challenge ~ts and FSM ~w",
                       [ ChalType, LeecFsmPid ] ).



-doc "Returns a textual description of the specified maybe-LEEC caller state.".
-spec maybe_caller_state_to_string( option( leec_caller_state() ) ) ->
                                                ustring().
maybe_caller_state_to_string( _MaybeLEECCallerState=undefined ) ->
    "no LEEC caller state/FSM";

maybe_caller_state_to_string( LEECCallerState ) ->
    caller_state_to_string( LEECCallerState ).
