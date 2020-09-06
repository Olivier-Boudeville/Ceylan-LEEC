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

			% Ex: [E, N, D] with E: publicExponent, N: modulus, D:
			% privateExponent.
			%
			raw :: crypto:rsa_private(),

			% Ex: b64 encodings of N and E.
			b64_pair :: { letsencrypt:binary_b64(), letsencrypt:binary_b64() },

			% Path of the RSA private key encoded in ASN.1 DER:
			file_path :: file_utils:file_path() } ).



% Key (ex: account one):
-record( key, {

	kty :: 'RSA',

	n :: term(),

	e :: term() } ).



% RSA JSON Web Signature:
-record( jws, {

		   alg = 'RS256' :: letsencrypt:jws_algorithm(),

		   url :: letsencrypt:uri(),

		   kid :: letsencrypt:uri(),

		   jwk :: letsencrypt:key(),

		   nonce = undefined :: maybe( letsencrypt:nonce() ) } ).



% Resulting certificate:
-record( certificate, {

			cert :: letsencrypt:bin_certificate(),

			key :: letsencrypt:bin_key() } ).
