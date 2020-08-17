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

-module(letsencrypt_ssl).
-author("Guillaume Bour <guillaume@bour.cc>").

-export([ create_private_key/2, get_cert_request/3,
		  generate_autosigned_certificate/3, write_certificate/3 ]).

-include_lib("public_key/include/public_key.hrl").


% Shorthands:

-type directory_path() :: file_utils:directory_path().
-type bin_directory_path() :: file_utils:bin_directory_path().
-type file_path() :: file_utils:file_path().

-type key_file_info() :: letsencrypt:key_file_info().
-type san() :: letsencrypt:san().
-type bin_certificate() :: letsencrypt:bin_certificate().



% Creates private key.
-spec create_private_key( maybe( key_file_info() ), directory_path() ) ->
		  letsencrypt:ssl_private_key().
create_private_key( undefined, CertDirPath ) ->

	% If not set, forges a unique filename to allow for multiple, concurrent
	% instances:
	%
	Uniq = basic_utils:get_process_specific_value(),

	DefaultFilename = text_utils:format( "letsencrypt-~B.key", [ Uniq ] ),

	% Safety measure:
	DefaultPath = file_utils:join( CertDirPath, DefaultFilename ),
	false = file_utils:is_existing_file( DefaultPath ),

	create_private_key( { new, DefaultFilename }, CertDirPath );


create_private_key( { new, KeyFilename }, CertDirPath ) ->

	KeyFilePath = file_utils:join( CertDirPath, KeyFilename ),

	case file_utils:is_existing_file( KeyFilePath ) of

		true ->
			trace_utils:warning_fmt( "A '~s' key file was already existing, "
				"it will be overwritten.", [ KeyFilePath ] );

		false ->
			ok

	end,

	Cmd = executable_utils:get_default_openssl_executable_path()
		++ " genrsa -out '" ++ KeyFilePath ++ "' 2048",

	case system_utils:run_executable( Cmd ) of

		{ _ReturnCode=0, _CommandOutput="" } ->
			ok;

		{ _ReturnCode=0, CommandOutput } ->
			trace_utils:warning_fmt(
			  "Command output when creating private key: ~s",
			  [ CommandOutput ] );

		{ ErrorCode, CommandOutput } ->
			trace_utils:error_fmt(
			  "Command for creating private key failed (error code: ~B): ~s",
			  [ ErrorCode, CommandOutput ] ),
			throw( { private_key_generation_failed, ErrorCode, CommandOutput } )

	end,

	case file_utils:is_existing_file( KeyFilePath ) of

		true ->
			ok;

		false ->
			throw( { generated_private_key_not_found, KeyFilePath } )

	end,

	% Now load it and return it as a ssl_private_key():
	create_private_key( KeyFilePath, CertDirPath );


create_private_key( KeyFilePath, _CertDirPath ) ->

	PemContent = file_utils:read_whole( KeyFilePath ),

	% ASN.1 DER encoded entry:
	[ KeyEntry ] = public_key:pem_decode( PemContent ),

	#'RSAPrivateKey'{ modulus=N, publicExponent=E, privateExponent=D } =
		public_key:pem_entry_decode( KeyEntry ),

	#{ raw => [ E, N, D ],
	   b64 => { letsencrypt_utils:b64encode( binary:encode_unsigned( N ) ),
				letsencrypt_utils:b64encode( binary:encode_unsigned( E ) ) },
	   file => KeyFilePath }.



-spec get_cert_request( net_utils:bin_fqdn(), bin_directory_path(),
						[ san() ] ) -> letsencrypt:ssl_csr().
get_cert_request( BinDomain, BinCertDirPath, SANs) ->

	Domain = text_utils:binary_to_string( BinDomain ),

	KeyFilePath = file_utils:join( BinCertDirPath, Domain ++ ".key" ),

	CertFilePath = file_utils:join( BinCertDirPath, Domain ++ ".csr" ),

	%trace_utils:debug_fmt( "CSR file path: ~s.", [ CertFilePath ] ),

	generate_certificate( request, BinDomain, CertFilePath, KeyFilePath, SANs ),

	RawCsr = file_utils:read_whole( CertFilePath ),

	[ { 'CertificationRequest', Csr, not_encrypted } ] =
		public_key:pem_decode( RawCsr ),

	%trace_utils:debug_fmt( "Decoded CSR: ~p", [ Csr ] ),

	letsencrypt_utils:b64encode( Csr ).



% Create temporary (1 day) certificate with subjectAlternativeName, returns its
% path.
%
% Used for the tls-sni-01 challenge.
%
-spec generate_autosigned_certificate( net_utils:string_fqdn(), file_path(),
									   [ san() ] ) -> file_path().
generate_autosigned_certificate( Domain, KeyFilePath, SANs ) ->

	CertFilePath = file_utils:join(
		system_utils:get_default_temporary_directory(),
		Domain ++ "-tlssni-autosigned.pem" ),

	generate_certificate(request, Domain, CertFilePath, KeyFilePath, SANs ),

	CertFilePath.




% Generates certificate.
-spec generate_certificate( 'request' | 'autosigned', net_utils:bin_fqdn(),
						file_path(), file_path(), [ san() ] ) -> void().
generate_certificate( request, BinDomain, OutCertPath, KeyfilePath, SANs ) ->

	BinAltNames = lists:foldl(
					fun( San, Acc ) ->
							<<Acc/binary, ", DNS:", San/binary>>
					end,
					_Acc0= <<"subjectAltName=DNS:", BinDomain/binary>>,
					_List=SANs ),

	Cmd = executable_utils:get_default_openssl_executable_path()
		++ " req -new -key '" ++ KeyfilePath ++ "' -out '"
		++ OutCertPath ++ text_utils:format( "' -subj '/CN=~s' -addext '~s'",
											 [ BinDomain, BinAltNames ] ),

	case system_utils:run_executable( Cmd ) of

		{ _ReturnCode=0, _CommandOutput="" } ->
			ok;

		{ _ReturnCode=0, CommandOutput } ->
			trace_utils:warning_fmt(
			  "Command output when generating certificate: ~s",
			  [ CommandOutput ] );

		{ ErrorCode, CommandOutput } ->
			trace_utils:error_fmt(
			  "Command for generating certificate failed (error code: ~B): ~s",
			  [ ErrorCode, CommandOutput ] ),
			throw( { certificate_generation_failed, ErrorCode, CommandOutput } )

	end.



% Writes specified certificate.
%
% Domain certificate only.
%
-spec write_certificate( net_utils:string_fqdn(), bin_certificate(),
						 directory_path() ) -> file_path().
write_certificate( Domain, BinDomainCert, CertDirPath ) ->

	CertFilePath = file_utils:join( CertDirPath, Domain ++ ".crt" ),

	%trace_utils:debug_fmt( "Domain certificate for '~s' (in '~s'): ~p.",
	%                     [ Domain, CertFilePath, BinDomainCert ] ),

	file_utils:write_whole( CertFilePath, BinDomainCert ),

	CertFilePath.
