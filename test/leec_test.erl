% Copyright (C) 2020-2020 Olivier Boudeville
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


% Very basic usage example for LEEC, based on irrelevant settings.
%
% Allows to check that LEEC can be used directly, out of a rebar3 context.
%
-module(leec_test).


% For run/0 export and al:
-include("test_facilities.hrl").


-spec run() -> no_return().
run() ->

	test_facilities:start( ?MODULE ),

	test_facilities:display( "Testing LEEC." ),

	% Not in an OTP context here, yet we need OTP applications such as LEEC to
	% work (ex: w.r.t. their .app being found, etc.):

	OrderedAppNames = letsencrypt:get_ordered_prerequisites(),

   % Build root directory from which prerequisite applications may be found:
	BuildRootDir = "..",

	% Updating ebin paths so that the corresponding *.app files are found:
	case otp_utils:prepare_for_execution( [ letsencrypt | OrderedAppNames ],
										  BuildRootDir ) of

		ready ->
			ok;

		{ lacking_app, AppName } ->
			throw( { lacking_prerequisite_app, AppName } )

	end,

	% Note that a webserver is unlikely to server that directory:
	WebrootDirPath = "/tmp",

	CertDirPath = "/tmp",

	% Expected to succeed:
	{ ok, LeecFsmPid } = letsencrypt:start( [ { mode, webroot },
		{ webroot_dir_path, WebrootDirPath },
		{ cert_dir_path, CertDirPath } ] ),

	% Unlikely to be relevant either:
	DomainName = "www.foobar.org",

	% Expected to fail:
	case letsencrypt:obtain_certificate_for( DomainName, LeecFsmPid,
						 letsencrypt:get_default_options( _Async=false ) ) of

		{ certificate_ready, BinCertFilePath } ->
			throw( { not_expected_to_succeed, BinCertFilePath } );

		{ error, Error } ->
			test_facilities:display_fmt( "As expected, an error is raised: ~p",
										 [ Error ] )

	end,

	test_facilities:stop().
