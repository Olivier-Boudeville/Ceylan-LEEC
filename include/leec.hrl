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


% To be able to be built also through rebar3, not only by Myriad's native build
% system:

-type void() :: basic_utils:void().
-type maybe( T ) :: basic_utils:maybe( T ).

-type table( K, V ) :: map_hashtable:map_hashtable( K, V ).

% Unused silencing:
-export_type([ void/0, maybe/1, table/2 ]).


% As records are so much clearer and relevant than maps in this context:


% TLS private key:
-record( tls_private_key, {

	% For example [E, N, D] with E: publicExponent, N: modulus, D:
	% privateExponent.
	%
	raw :: leec:rsa_private_key(),

	% For example b64 encodings of N and E.
	b64_pair :: { leec:binary_b64(), leec:binary_b64() },

	% Absolute path of the RSA private key encoded in ASN.1 DER:
	file_path :: file_utils:bin_file_path() } ).



% TLS public key (e.g. the account one):
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
	url :: maybe( leec:bin_uri() ),

	% Key identifier; e.g.
	% "https://acme-staging-v02.api.letsencrypt.org/acme/acct/16082748"
	%
	kid :: maybe( leec:bin_uri() ),

	% The public key used to verify the JWS, in order to authenticate future
	% requests from the account to the ACME server:
	%
	jwk :: maybe( leec:tls_public_key() ),

	% The nonce that shall be used for next sending:
	nonce = undefined :: maybe( leec:nonce() ) } ).



% Resulting certificate:
-record( certificate, {

	cert :: leec:bin_certificate(),

	key :: leec:bin_key() } ).



% For internal use only:


% State of a LEEC FSM instance:
-record( le_state, {

	% ACME environment:
	env = prod :: 'staging' | 'prod',

	% URI directory, fetched from ACME servers at startup (that is table of the
	% URIs to be called depending on operations being needed regarding
	% certificates):
	%
	directory_map = undefined :: maybe( leec:directory_map() ),

	% Directory where certificates are to be stored:
	cert_dir_path = <<"/tmp">> :: file_utils:bin_directory_path(),

	% The filename (relative to cert_dir_path) of the target certificate (CSR)
	% private key file (if any) for the domain(s) of interest.
	%
	cert_key_file = undefined :: maybe( file_utils:bin_file_path() ),

	% For example mode = webroot.
	mode = undefined :: maybe( leec:le_mode() ),

	% If mode is 'webroot':
	webroot_dir_path = undefined :: maybe( file_utils:bin_directory_path() ),

	% If mode is 'standalone':
	port = 80 :: net_utils:tcp_port(),

	% An (optional) identifier specified by the user when starting a LEEC
	% instance (before requesting an operation related to any specific domain)
	% to ensure the uniqueness thereof (e.g. regarding the name of its agent key
	% file):
	%
	% (might be added in the future)
	%
	%user_id :: maybe( term() ),

	% State-related data:

	% Current nonce to be specified, in order to avoid any replay attack:
	nonce = undefined :: maybe( leec:nonce() ),

	domain = undefined :: maybe( net_utils:bin_fqdn() ),

	% The Subject Alternative Names of interest:
	sans = [] :: [ leec:san() ],

	% Information regarding the key of the LEEC agent; it is either created or
	% read from any user-specified file:
	%
	agent_key_file_info = undefined :: maybe( leec:agent_key_file_info() ),

	% The TLS private key the LEEC agent is relying on:
	agent_private_key = undefined :: maybe( leec:tls_private_key() ),

	% No need to record the path to the private key file of the LEEC agent, as
	% it is a field of the previous attribute:
	%
	%agent_key_file_path = undefined :: maybe( file_utils:file_path() ),

	% JSON Web Signature of the private key of the LEEC agent:
	jws = undefined :: maybe( leec:jws() ),

	% The public key returned by the ACME server when an account is obtained
	% (its private key remains on the ACME server):
	%
	account_key :: maybe( leec:tls_public_key() ),

	order = undefined :: maybe( leec:order_map() ),

	% Known challenges, per URI:
	challenges = #{} :: leec:uri_challenge_map(),

	% Certificate request options.
	cert_req_option_map =
		leec:get_default_cert_request_options() :: leec:cert_req_option_map(),

	% Useful to be able to switch JSON parsers at runtime, yet to avoid repeated
	% initializations thereof:
	%
	json_parser_state :: json_utils:parser_state(),

	% To re-use TCP connections, on a per FSM basis:
	tcp_connection_cache :: leec:tcp_connection_cache() } ).
