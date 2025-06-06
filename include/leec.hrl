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
% Creation date: 2020.


% To be able to be built also through rebar3, not only by Myriad's native build
% system:

-type void() :: basic_utils:void().
-type option( T ) :: basic_utils:option( T ).

-type table( K, V ) :: map_hashtable:map_hashtable( K, V ).

% Unused silencing:
-export_type([ void/0, option/1, table/2 ]).


% As records are so much clearer and relevant than maps in this context:


% The TLS private key (locally generated and never sent) of the target
% certificate:
%
-record( tls_private_key, {

	% For example [E, N, D] with E: publicExponent, N: modulus, D:
	% privateExponent.
	%
	raw :: leec:rsa_private_key(),

	% For example b64 encodings of N and E.
	b64_pair :: { leec:binary_b64(), leec:binary_b64() },

	% Absolute path of the RSA private key encoded in ASN.1 DER:
	file_path :: file_utils:bin_file_path() } ).



% The TLS public key (locally generated) of the target certificate:
-record( tls_public_key, {

	% Key type:
	kty :: 'RSA',

	n :: text_utils:bin_string(),

	e :: text_utils:bin_string() } ).



% RSA JSON Web Signature:
-record( jws, {

	% The signing algorithm:
	alg = 'RS256' :: leec:jws_algorithm(),

	% For example "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"
	url :: option( leec:bin_uri() ),

	% Key identifier; e.g.
	% "https://acme-staging-v02.api.letsencrypt.org/acme/acct/16082748"
	%
	kid :: option( leec:bin_uri() ),

	% The public key used to verify the JWS, in order to authenticate future
	% requests from the account to the ACME server:
	%
	jwk :: option( leec:tls_public_key() ),

	% The nonce that shall be used for next sending:
	nonce = undefined :: option( leec:nonce() ) } ).



% For internal use only:


% State of a LEEC FSM instance for the http-01 challenge:
-record( leec_http_state, {

	% The selected ACME environment:
	environment = production :: leec:environment(),

	% URI directory, fetched from ACME servers at startup (that is table of the
	% URIs to be called depending on operations being needed regarding
	% certificates):
	%
	directory_map = undefined :: option( leec:directory_map() ),

	% Directory where certificates are to be stored:
	cert_dir_path :: file_utils:bin_directory_path(),

	% The filename (relative to cert_dir_path) of the target certificate (CSR)
	% private key file (if any) for the domain(s) of interest.
	%
	cert_key_file = undefined :: option( file_utils:bin_file_path() ),

	% The absolute path to the file containing the private key of the target
	% certificate:
	%
	cert_priv_key_path = undefined :: option( leec:cert_priv_key_file_path() ),

	% Interfacing mode; for example webroot.
	interfacing_mode = undefined :: option( leec:web_interfacing_mode() ),

	% If mode is 'webroot':
	webroot_dir_path = undefined :: option( file_utils:bin_directory_path() ),

	% If mode is 'standalone':
	port = 80 :: net_utils:tcp_port(),

	% An (optional) identifier specified by the user when starting a LEEC
	% instance (before requesting an operation related to any specific domain)
	% to ensure the uniqueness thereof (e.g. regarding the name of its agent key
	% file):
	%
	% (might be added in the future)
	%
	%user_id :: option( term() ),

	% State-related data:

	% Current nonce to be specified, in order to avoid any replay attack:
	nonce = undefined :: option( leec:nonce() ),

	domain = undefined :: option( net_utils:bin_fqdn() ),

	% The Subject Alternative Names of interest:
	sans = [] :: [ leec:san() ],

	% Information regarding the key of the LEEC agent; it is either created or
	% read from any user-specified file:
	%
	agent_key_file_info = undefined :: option( leec:agent_key_file_info() ),

	% The TLS private key the LEEC agent is relying on:
	agent_private_key = undefined :: option( leec:tls_private_key() ),

	% No need to record the path to the private key file of the LEEC agent, as
	% it is a field of the previous attribute:
	%
	%agent_key_file_path = undefined :: option( file_utils:file_path() ),

	% JSON Web Signature of the private key of the LEEC agent:
	jws = undefined :: option( leec:jws() ),

	% The public key returned by the ACME server when an account is obtained
	% (its private key remains on the ACME server):
	%
	account_key :: option( leec:tls_public_key() ),

	order = undefined :: option( leec:order_map() ),

	% Known challenges, per URI:
	challenges = #{} :: leec:uri_challenge_map(),

	% Certificate request options.
	cert_req_option_map :: leec:cert_req_option_map(),

	% Useful to be able to switch JSON parsers at runtime, yet to avoid repeated
	% initializations thereof:
	%
	json_parser_state :: json_utils:parser_state(),

	% To re-use TCP connections, on a per FSM basis:
	tcp_connection_cache :: leec:tcp_connection_cache() } ).




% State of a LEEC instance for the dns-01 challenge:
-record( leec_dns_state, {

	% The selected ACME environment:
	environment = production :: leec:environment(),

	% Directory where certbot is to store its state:
	state_dir_path :: file_utils:bin_directory_path(),

	% Directory where work data is to be written:
	work_dir_path :: file_utils:bin_directory_path(),

	% Path to the certbot executable:
	certbot_path :: file_utils:bin_executable_path(),

	% Directory where DNS credentials are to be read:
	credentials_dir_path :: file_utils:bin_directory_path(),

	% Directory where certificates are to be stored:
	cert_dir_path :: file_utils:bin_directory_path(),

	% The filename (relative to cert_dir_path) of the target certificate (CSR)
	% private key file (if any) for the domain(s) of interest.
	%
	cert_key_file = undefined :: option( file_utils:bin_file_path() ),

	domain = undefined :: option( net_utils:bin_fqdn() )

	% Email address used for registration and recovery contact:
	% Not relevant here: email :: option( email_utils:bin_email_address() )

 } ).
