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
-type ssl_private_key() :: letsencrypt:ssl_private_key().


% Creates private key.
-spec create_private_key( maybe( key_file_info() ), bin_directory_path() ) ->
		  ssl_private_key().
create_private_key( _KeyFileInfo=undefined, BinCertDirPath ) ->

	% If not set, forges a unique filename to allow for multiple, concurrent
	% instances:

	Uniq = basic_utils:get_process_specific_value(),

	DefaultFilename = text_utils:format( "letsencrypt-agent-~B.key", [ Uniq ] ),

	% Safety measure:
	DefaultPath = file_utils:join( BinCertDirPath, DefaultFilename ),
	false = file_utils:is_existing_file( DefaultPath ),

	create_private_key( { new, DefaultFilename }, BinCertDirPath );


create_private_key( _KeyFileInfo={ new, KeyFilename }, BinCertDirPath ) ->

	KeyFilePath = file_utils:join( BinCertDirPath, KeyFilename ),

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
			trace_utils:warning_fmt( "Private key creation successful, yet "
			  "following output was made: ~s.", [ CommandOutput ] );

		{ ErrorCode, CommandOutput } ->
			trace_utils:error_fmt(
			  "Command for creating private key failed (error code: ~B): ~s.",
			  [ ErrorCode, CommandOutput ] ),
			throw( { private_key_generation_failed, ErrorCode, CommandOutput } )

	end,

	case file_utils:is_existing_file( KeyFilePath ) of

		true ->
			ok;

		false ->
			throw( { generated_private_key_not_found, KeyFilePath } )

	end,

	% Now load it, and return it as a ssl_private_key():
	create_private_key( KeyFilePath, BinCertDirPath );


create_private_key( _KeyFileInfo=KeyFilePath, _BinCertDirPath ) ->

	PemContent = file_utils:read_whole( KeyFilePath ),

	% ASN.1 DER encoded entry:
	[ KeyEntry ] = public_key:pem_decode( PemContent ),

	#'RSAPrivateKey'{ modulus=N, publicExponent=E, privateExponent=D } =
		public_key:pem_entry_decode( KeyEntry ),

	% Returning a corresponding ssl_private_key():
	#{ raw => [ E, N, D ],
	   b64 => { letsencrypt_utils:b64encode( binary:encode_unsigned( N ) ),
				letsencrypt_utils:b64encode( binary:encode_unsigned( E ) ) },
	   file => KeyFilePath }.



% Returns a CSR certificate request.
-spec get_cert_request( net_utils:bin_fqdn(), bin_directory_path(),
						[ san() ] ) -> letsencrypt:ssl_csr().
get_cert_request( BinDomain, BinCertDirPath, SANs ) ->

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



% Generates a domain certificate.
-spec get_domain_certificate( bin_domain(), bin_certificate(),
							  bin_directory_path() ) -> file_path().
get_domain_certificate( BinDomain, BinDomainCert, BinCertDirPath ) ->

	Domain = text_utils:binary_to_string( BinDomain ),

	CertFilePath = file_utils:join( BinCertDirPath, Domain ++ ".crt" ),

	file_utils:write_whole( CertFilePath, BinDomainCert ),

	CertFilePath.



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

	generate_certificate( autosigned, Domain, CertFilePath, KeyFilePath,
						  SANs ).


% Generates certificate.
-spec generate_certificate( 'request' | 'autosigned', net_utils:bin_fqdn(),
						file_path(), file_path(), [ san() ] ) -> void().
generate_certificate( request, BinDomain, OutCertPath, KeyfilePath, SANs ) ->

	% First, generates a configuration file, in the same directory as the target
	% certificate:

	AllNames = [ BinDomain | SANs ],

	% {any_string(), basic_utils:count()} pairs:
	NumberedNamePairs = lists:zip( AllNames, 
								   lists:seq( 1, length( AllNames) ) ),

	ConfData = [
		"[req]\n",
		"distinguished_name = req_distinguished_name\n",
		"x509_extensions = v3_req\n",
		"prompt = no\n",
		"[req_distinguished_name]\n",
		"CN = ", BinDomain, "\n",
		"[v3_req]\n",
		"subjectAltName = @alt_names\n",
		"[alt_names]\n"
	] ++ [
		[ "DNS.", text_utils:integer_to_string( Index ), " = ", Name, "\n" ] 
		  || { Name, Index } <- NumberedNamePairs ],

	ConfDir = filename:dirname(OutName),

	ConfFile = filename:join(ConfDir, "letsencrypt_san_openssl." ++ letsencrypt_utils:str(Domain) ++ ".cnf"),
	ok = file:write_file(ConfFile, Cnf),
	Cmd = io_lib:format("openssl req -new -key '~s' -sha256 -out '~s' -config '~s'",
						[Keyfile, OutName, ConfFile]),
	Cmd1 = case Type of
		request    -> [Cmd | " -reqexts v3_req" ];
		autosigned -> [Cmd | " -extensions v3_req -x509 -days 1" ]
	end,
	_Status = os:cmd(Cmd1),
	file:delete(ConfFile),
	{ok, OutName}.


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
