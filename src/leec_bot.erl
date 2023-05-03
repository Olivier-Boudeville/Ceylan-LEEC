% Copyright (C) 2023-2023 Olivier Boudeville
%
% This file is part of the Ceylan-LEEC library, a fork of the Guillaume Bour's
% letsencrypt-erlang library, released under the same licence.
%
% This file was created on Monday, May 1, 2023.


% @doc This module helps the <b>usage of certification bots</b>, in pratice
% cerbot (see https://certbot.eff.org/pages/about).
%
% The prerequistes and conventions described in
% https://leec.esperide.org/#wildcard-domain-certificates-with-the-dns-01-challenge
% are expected to have been respected here.
%
-module(leec_bot).


% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com").


-type certbot_credentials_file_path() :: file_path().
% For example a path like
% "/etc/xdg/universal-server/leec-ovh-credentials-for-foobar.org.txt".

-type dns_provider() :: 'ovh'.
% A currently supported DNS provider.


-export_type([ certbot_credentials_file/0, dns_provider/0 ]).

-export([ get_certbot_executable_path/0 ]).




% For the records introduced:
%-include("leec.hrl").


% Defines:

%-define( ovh_api_base_url, "https://api.ovh.com" ).



% Shorthands:

-type file_path() :: file_utils:file_path().

-type executable_path() :: executable_utils:executable_path().

-type domain() :: leec:domain().


% @doc Returns a path to the certbot executable.
%
% Note that any plugin for a DNS provider of choice shall have been installed.
%
% For example, on Arch Linux with the OVH DNS provider: `pacman -Sy certbot
% certbot-dns-ovh'.
%
% Throws an exception if the executable is not found.
%
-spec get_certbot_executable_path() -> executable_path().
get_certbot_executable_path() ->
	% Typically "/usr/bin/certbot":
	case executable_utils:lookup_executable( "certbot" ) of

		false ->
			throw( certbot_executable_not_found );

		ExecPath ->
			ExecPath

	end.


% @doc Generates (synchronously) the requested certificate.
-spec obtain_certificate_for( domain(), dns_provider() ) -> void().
obtain_certificate_for( Domain, _DNSProvider=ovh ) ->


obtain_certificate_for( Domain, DNSProvider ) ->
	throw( { unsupported_dns_provider, DNSProvider, Domain } ).
