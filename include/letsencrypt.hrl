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



% As records are so much clearer and relevant than maps in this context:


% TLS private key:
-record( tls_private_key, {

  % Ex: [E, N, D] with E: publicExponent, N: modulus, D: privateExponent.
  raw :: crypto:rsa_private(),

  % Ex: b64 encodings of N and E.
  b64_pair :: { letsencrypt:binary_b64(), letsencrypt:binary_b64() },

  % Path of the RSA private key encoded in ASN.1 DER:
  file_path :: file_utils:file_path() } ).



% TLS public key (ex: the account one):
-record( tls_public_key, {

  % Key type:
  kty :: 'RSA',

  n :: text_utils:bin_string(),

  e :: text_utils:bin_string() } ).



% RSA JSON Web Signature:
-record( jws, {

  % The signing algorithm:
  alg = 'RS256' :: letsencrypt:jws_algorithm(),

  % Ex: "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"
  url :: letsencrypt:bin_uri(),

  % Key identifier; ex:
  % "https://acme-staging-v02.api.letsencrypt.org/acme/acct/16082748"
  %
  kid :: letsencrypt:bin_uri(),

  % The public key used to verify the JWS, in order to authenticate future
  % requests from the account to the ACME server:
  %
  jwk :: letsencrypt:tls_public_key(),

  % The nonce that shall be used for next sending:
  nonce = undefined :: maybe( letsencrypt:nonce() ) } ).



% Resulting certificate:
-record( certificate, {

  cert :: letsencrypt:bin_certificate(),

  key :: letsencrypt:bin_key() } ).



% For internal use only:

% State of a LEEC FSM instance:
-record( le_state, {

	% ACME environment:
	env = prod :: 'staging' | 'prod',

	% URI directory, fetched from ACME servers at startup (i.e. table of the
	% URIs to be called depending on needs regarding certificates):
	%
	directory_map = undefined ::
		basic_utils:maybe( file_utils:directory_map() ),

	% Directory where certificates are to be stored:
	cert_dir_path = <<"/tmp">> :: file_utils:bin_directory_path(),

	% Ex: mode = webroot.
	mode = undefined :: basic_utils:maybe( letsencrypt:le_mode() ),

	% If mode is 'webroot':
	webroot_dir_path = undefined ::
	  basic_utils:maybe( file_utils:bin_directory_path() ),

	% If mode is 'standalone':
	port = 80 :: net_utils:tcp_port(),

	intermediate_cert = undefined ::
	  basic_utils:maybe( letsencrypt:bin_certificate() ),


	% State-related data:

	% Current nonce to be specified, in order to avoid any replay attack:
	nonce = undefined :: basic_utils:maybe( letsencrypt:nonce() ),

	domain = undefined :: basic_utils:maybe( net_utils:bin_fqdn() ),

	% The Subject Alternative Names of interest:
	sans = [] :: [ letsencrypt:san() ],

	% Information regarding the key of the LEEC agent:
	agent_key_file_info = undefined ::
	  basic_utils:maybe( letsencrypt:agent_key_file_info() ),

	% The TLS private key that the LEEC agent generated at startup:
	agent_private_key = undefined ::
	  basic_utils:maybe( letsencrypt:tls_private_key() ),

	% JSON Web Signature of the private key of the LEEC agent:
	jws = undefined :: basic_utils:maybe( letsencrypt:jws() ),

	% The public key returned by the ACME server on account creation:
	account_key :: letsencrypt:tls_public_key(),

	order = undefined :: basic_utils:maybe( letsencrypt:directory_map() ),

	% Known challenges, per URI:
	challenges = #{} :: letsencrypt:uri_challenge_map(),

	% Path to the private key file of the LEEC agent:
	agent_key_file_path = undefined ::
	  basic_utils:maybe( file_utils:file_path() ),

	% API options:
	option_map = letsencrypt:get_default_options() :: letsencrypt:option_map(),

	% Useful to be able to switch JSON parsers at runtime, yet to avoid repeated
	% initializations thereof:
	%
	json_parser_state :: json_utils:parser_state() }).
