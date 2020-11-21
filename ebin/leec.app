% Description of the LEEC OTP application, typically used by rebar3.
%
% LEEC is the Ceylan fork of letsencrypt-erlang, a letsencrypt.org client
% library for Erlang.

% Note: if this file is named leec.app, it is a *generated* file, whose real
% source is conf/leec.app.src, from which _build/lib/leec/ebin/leec.app is
% obtained and copied to ebin/leec.app; finally src/leec.app.src is a mere
% symlink to this last file, so we have:
%
% ./conf/leec.app.src [only real source]
% ./_build/lib/leec/ebin/leec.app [generated]
% ./ebin/leec.app [copy of generated]
% ./src/leec.app.src -> ../ebin/leec.app
%
% For more information see the Ceylan-Myriad 'rebar3-create-app-file' make
% target and its associated comments.

% See also:
% - http://erlang.org/doc/man/app.html
% - https://learnyousomeerlang.com/building-otp-applications


{application, leec, [

  {description, "A letsencrypt.org client library for Erlang, the Ceylan fork of letsencrypt-erlang"},

  {vsn, "0.5.0"},

  {registered, []},

  % Regarding Myriad, see http://myriad.esperide.org/myriad.html#otp
  %
  % Elli is useful iff in standalone mode (i.e. if needing to run our own
  % webserver).
  %
  % Note that, to select the JSON parser to use, 'jsx' might be replaced by
  % 'jiffy' here:
  %
  {applications, [kernel, stdlib, shotgun, jsx, elli, myriad]},

  {env,[]},

  % Flat hierarchy in ebin here:
  {modules, [letsencrypt, letsencrypt_api, letsencrypt_elli_handler, letsencrypt_jws, letsencrypt_tls, letsencrypt_utils]},

  {maintainers, ["Olivier Boudeville (original author of letsencrypt-erlang: Guillaume Bour)"]},

  {licenses, ["Apache 2.0"]},

  % Passive application, so no 'mod' entry applies.

  {links, [ {"Official website (maybe some day)", "http://leec.esperide.org" },
			{"Github", "https://github.com/Olivier-Boudeville/letsencrypt-erlang"} ]},

  {build_tools, ["rebar"]},

   % Include escript & configuration into hex package:
  {include_files, ["bin/eletsencrypt", "etc/eletsencrypt.yml"]}

 ]}.
