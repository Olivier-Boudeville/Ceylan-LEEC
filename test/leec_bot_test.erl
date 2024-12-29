% Copyright (C) 2023-2025 Olivier Boudeville
%
% This file is part of the LEEC (Let's Encrypt Erlang with Ceylan) library.
%
% Licensed under the Apache License, Version 2.0 (the "License");
% you may not use this file except in compliance with the License.
% You may obtain a copy of the License at
%
% http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS,
% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
% See the License for the specific language governing permissions and
% limitations under the License.
%
% Author: Olivier Boudeville [olivier (dot) boudeville (at) esperide (dot) com]
% Creation date: Friday, May 5, 2023.

-module(leec_bot_test).

-moduledoc """
Basic usage example of the **Ceylan-LEEC certbot support**, based on irrelevant
settings.

Allows to check that the LEEC certbot support can be used directly, out of a
rebar3 context.
""".


% For run/0 export and al:
-include_lib("myriad/include/test_facilities.hrl").



-doc "Performs the actual dns-01 challenge test.".
-spec run_actual_test() -> void().
run_actual_test() ->

	TestCredDir = "leec-test-cred-dir",
	file_utils:create_directory_if_not_existing( TestCredDir ),

	TestWorkDir = "leec-test-work-dir",
	file_utils:create_directory_if_not_existing( TestWorkDir ),

	TestCertDir = "leec-test-cert-dir",
	file_utils:create_directory_if_not_existing( TestCertDir ),

	% The options retained for the LEEC FSM:
	BaseLEECOpts = [ { environment, staging },
					 { cred_dir_path, TestCredDir },
					 { work_dir_path, TestWorkDir },
					 { cert_dir_path, TestCertDir } ],

	ChallengeType = 'dns-01',

	DNSProvider = ovh,

	LeecCallerState = case leec:start( ChallengeType, BaseLEECOpts ) of

		{ ok, CallerState } ->
			CallerState;

		OtherStartRes ->
			throw( { leec_start_failed, OtherStartRes } )

	 end,

	% Unlikely to be relevant either:
	DomainName = "www.foobar.org",

	% Typically "leec-ovh-credentials-for-www.foobar.org.txt":
	CredFilePath = leec:get_credentials_path_for( DNSProvider, DomainName,
												  TestCredDir ),

	% Of course no relevant content, but at least exists:
	file_utils:create_empty_file( CredFilePath ),

	% To avoid a 'Unsafe permissions on credentials configuration file' warning:
	file_utils:change_permissions( CredFilePath, owner_read ),


	BaseCertReqOpts = leec:get_default_cert_request_options( ChallengeType,
															 _Async=false ),


	CertReqOpts = BaseCertReqOpts#{ dns_provider => DNSProvider },

	ContinueTest = false,
	%ContinueTest = true,

	case ContinueTest of

		true ->
			case leec:obtain_certificate_for( DomainName, LeecCallerState,
											  CertReqOpts ) of

				{ certificate_ready, BinCertFilePath, BinPrivKeyFilePath } ->
					throw( { not_expected_to_succeed, BinCertFilePath,
							 BinPrivKeyFilePath } );

				{ error, Error } ->
					test_facilities:display_fmt(
						"As expected, an error is raised: ~p", [ Error ] )

			end;

		false ->
			basic_utils:ignore_unused( CertReqOpts ),
			test_facilities:display_fmt( "No attempt to generate a certificate "
				"here for '~ts' (bound to fail in this context).",
				[ DomainName ] )

	end,

	file_utils:remove_directories_if_existing(
		[ TestCredDir, TestWorkDir, TestCertDir ] ).



-spec run() -> no_return().
run() ->

	test_facilities:start( ?MODULE ),

	test_facilities:display( "Testing the LEEC support for certbot." ),

	% Not in an OTP context here, yet we need OTP applications such as LEEC to
	% work (e.g. w.r.t. their .app being found, etc.):

	% Base build root directory from which prerequisite applications may be
	% found:
	%
	BuildRootDir = "..",

	OrderedAppNames = otp_utils:prepare_for_execution( _ThisApp=leec,
													   BuildRootDir ),

	% Retain all applications but LEEC itself, so that we can run LEEC as we
	% want (anyway it is a library application):
	%
	{ leec, PrereqAppNames } =
		list_utils:extract_last_element( OrderedAppNames ),

	trace_utils:info_fmt( "Resulting prerequisite applications to start, "
						  "in order: ~w.", [ OrderedAppNames ] ),

	otp_utils:start_applications( PrereqAppNames ),

	case leec:can_perform_dns_challenges() of

		true ->
			run_actual_test();

		false->
			test_facilities:display( "LEEC lacks prerequisites in order to "
				"perform DNS challenges, test not performed." )

	end,

	test_facilities:stop().
