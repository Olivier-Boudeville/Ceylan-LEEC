% Description of the LEEC OTP library application, typically used by rebar3.
%
% LEEC is the Ceylan fork of letsencrypt-erlang, a letsencrypt.org client
% library for Erlang.

% Note: if this file is named leec.app, it is a *generated* file, whose real
% source is conf/leec.app.src, from which _build/lib/leec/ebin/leec.app
% is obtained and copied to ebin/leec.app; finally src/leec.app.src is a
% mere symlink to this last file, so we have:
%
% ./conf/leec.app.src [only real source]
% ./_build/lib/leec/ebin/leec.app
% ./ebin/leec.app
% ./src/leec.app.src -> ../ebin/leec.app
%
% For more information see the Ceylan-Myriad 'rebar3-create-app-file' make
% target and its associated comments.


% See also:
% - http://erlang.org/doc/man/app.html
% - https://learnyousomeerlang.com/building-otp-applications


{application, leec, [

  {description, "Ceylan-LEEC, a letsencrypt.org client library for Erlang, the Ceylan fork of letsencrypt-erlang, as an OTP library application here (see http://leec.esperide.org)"},

  {vsn, "1.1.3"},

  {registered, []},

  % Shotgun was used by default with OTP/rebar3 builds, whereas native httpc was
  % used by default with our custom build.
  % Both are still supported, yet now in both cases we rely on native httpc.
  %
  % Regarding Myriad, see http://myriad.esperide.org/myriad.html#otp
  %
  % Elli is useful iff in standalone mode (i.e. if needing to run our own
  % webserver); LEEC currently does not use it.
  %
  % Note that, to select the JSON parser to use, 'jsx' might be replaced by
  % 'jiffy' below.
  %
  % Finally, this 'applications' entry must be consistent with
  % conf/rebar.config.template (source of the actual rebar.config) and with the
  % HTTPC_OPT variable (see GNUmakevars.inc).

  % Complete with elli (default: jsx):
  %{applications, [kernel, stdlib, shotgun, jsx, elli, myriad]},

  % Complete with elli, if preferring jiffy:
  %{applications, [kernel, stdlib, shotgun, jiffy, myriad]},

  % jsx, no elli nor shotgun is our current default:
  {applications, [kernel, stdlib, jsx, myriad]},

  {env,[]},

  % Flat hierarchy in ebin here:
  {modules, [leec, leec_api, leec_elli_handler, leec_jws, leec_tls, leec_utils]},

  {maintainers, ["Olivier Boudeville (original author of letsencrypt-erlang: Guillaume Bour)"]},

  {licenses, ["Apache 2.0"]},

  % Library application, not an active one, so no specific behaviour of its own:
  % {mod, {leec_app,[]}}

  {links, [ {"Official website", "http://leec.esperide.org" },
			{"Github", "https://github.com/Olivier-Boudeville/Ceylan-LEEC"} ]}

  %{build_tools, ["rebar"]},

  % Include escript & configuration into hex package:
  %{include_files, ["bin/eletsencrypt", "etc/eletsencrypt.yml"]}

 ]}.
