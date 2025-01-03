% Copyright (C) 2020-2025 Olivier Boudeville
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
% Creation date: Wednesday, October 28, 2020.

-module(leec_test).

-moduledoc """
Very **basic usage example for Ceylan-LEEC**, mainly for the http-01 challenge,
based on mostly irrelevant settings.

Allows to check that LEEC can be used directly, out of a rebar3 context.
""".


% For run/0 export and al:
-include_lib("myriad/include/test_facilities.hrl").


-spec run() -> no_return().
run() ->

	test_facilities:start( ?MODULE ),

	test_facilities:display( "Testing LEEC." ),

	test_facilities:display( "The version of this currently tested LEEC "
		"library is ~ts (i.e. ~w).", [ leec_utils:get_leec_version_string(),
									   leec_utils:get_leec_version() ] ),

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

	% Note that a webserver is unlikely to serve that directory:
	WebrootDirPath = "/tmp",

	CertDirPath = "/tmp",

	% The options retained for the first LEEC FSM:
	BaseLEECOpts = [ { environment, staging },
					 { interfacing_mode, webroot },
					 { webroot_dir_path, WebrootDirPath },
					 { cert_dir_path, CertDirPath } ],

	ChallengeType = 'http-01',

	% No agent private key specified, it will be generated (with a generated
	% name); expected to succeed:
	%
	FirstLeecCallerState = case leec:start( ChallengeType, BaseLEECOpts ) of

		{ ok, FirstLCS } ->
			FirstLCS;

		OtherFirstStartRes ->
			throw( { leec_first_start_failed, OtherFirstStartRes } )

	 end,

	BinKeyPath = case leec:get_agent_key_path( FirstLeecCallerState ) of

		undefined ->
			throw( { no_agent_key_path_obtained, FirstLeecCallerState } );

		BinKPath ->
			trace_utils:info_fmt( "Obtained agent key path '~ts'.",
								  [ BinKPath ] ),
			BinKPath

	end,

	file_utils:is_existing_file_or_link( BinKeyPath ) orelse
		throw( { non_existing_agent_key_file, BinKeyPath } ),

	% For the second LEEC FSM, to rely on the same account:
	SecondLEECOpts = [ { agent_key_file_path, BinKeyPath } | BaseLEECOpts ],

	_SecondLeecCallerState = case leec:start( ChallengeType, SecondLEECOpts ) of

		{ ok, SecondLCS }  ->
			SecondLCS;

		OtherSecondStartRes ->
			throw( { leec_second_start_failed, OtherSecondStartRes } )

	 end,


	% Unlikely to be relevant either:
	DomainName = "www.foobar.org",

	% As no webserver is running and DomainName is not controlled, would be
	% expected to fail with:
	%
	%[debug] [<0.x.0>] Check resulted in switching from 'pending' to 'invalid'
	%state.
	%[debug] [<0.x.0>] Entering the 'invalid' state.
	%
	% <----------------
	% [error] [<0.x.0>] Reached the (stable) 'invalid' state for domain
	% 'www.foobar.org'.
	%  ---------------->
	%
	% {"init terminating in
	% do_boot",{{nocatch,{challenges_could_not_be_validated,<0.x.0>}},
	% [{leec,wait_challenges_valid,3,[{file,"leec.erl"},{line,L}]},
	%
	ContinueTest = false,
	%ContinueTest = true,

	case ContinueTest of

		true ->
			case leec:obtain_certificate_for( DomainName, FirstLeecCallerState,
					leec:get_default_cert_request_options( _Async=false ) ) of

				{ certificate_generation_success, BinCertFilePath,
				  BinPrivKeyFilePath } ->
					throw( { not_expected_to_succeed, BinCertFilePath,
							 BinPrivKeyFilePath } );

				{ certificate_generation_failure, Error } ->
					test_facilities:display_fmt(
						"As expected, an error is raised: ~p", [ Error ] )

			end;

		false ->
			test_facilities:display_fmt( "No attempt to generate a certificate "
				"here for '~ts' (bound to fail in this context).",
				[ DomainName ] )

	end,

	test_facilities:stop().
