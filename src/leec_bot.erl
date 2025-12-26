% Copyright (C) 2023-2026 Olivier Boudeville
%
% This file is part of the Ceylan-LEEC library, a fork of the Guillaume Bour's
% letsencrypt-erlang library, released under the same licence.
%
% This file was created on Monday, May 1, 2023.

-module(leec_bot).

-moduledoc """
This module helps the **usage of certification bots**, in practice cerbot (see
<https://certbot.eff.org/pages/about>).

The prerequistes and conventions described in
<https://leec.esperide.org/#wildcard-domain-certificates-with-the-dns-01-challenge>
are expected to have been respected here.
""".


% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com)").


-doc """
For example a path like
"/etc/xdg/universal-server/leec-ovh-credentials-for-foobar.org.txt".
""".
-type certbot_credentials_file_path() :: file_path().


-doc "A currently supported DNS provider.".
-type dns_provider() :: leec:dns_provider().


-export_type([ certbot_credentials_file_path/0, dns_provider/0 ]).


-export([ init_bot/2 ]).


% "Static" exports:
-export([ get_certbot_executable_path/0 ]).




% For the records introduced:
-include("leec.hrl").


% Defines:

%-define( ovh_api_base_url, "https://api.ovh.com" ).




% Type shorthands:

-type file_path() :: file_utils:file_path().
-type bin_directory_path() :: file_utils:bin_directory_path().

-type command_line_element() :: cmd_line_utils:command_line_element().

-type executable_path() :: executable_utils:executable_path().
-type bin_email_address() :: email_utils:bin_email_address().

-type bridge_spec() :: trace_bridge:bridge_spec().

-type bin_domain() :: leec:bin_domain().
-type leec_dns_state() :: leec:leec_dns_state().
-type creation_outcome() :: leec:creation_outcome().



-doc """
Initialises the LEEC bot for the dns-01 challenge.

Returns the PID of (currently) a pseudo-FSM process (can be seen as a
single-state FSM).
""".
-spec init_bot( leec_dns_state(), option( bridge_spec() ) ) -> no_return().
init_bot( LDState, MaybeBridgeSpec ) ->

    trace_bridge:register_if_not_already( MaybeBridgeSpec ),

    cond_utils:if_defined( leec_debug_bot, trace_bridge:debug_fmt(
        "Started LEEC bot with ~ts.", [ leec:state_to_string( LDState ) ] ) ),

    bot_main_loop( LDState ).



-doc "Main loop of the LEEC bot.".
-spec bot_main_loop( leec_dns_state() ) -> no_return().
bot_main_loop( LDState ) ->

    receive

        % We could mimic as much as possible the message exhange patterns of
        % http-01 with:
        %
        %{ '$gen_call', _GenStatemIds={ _CallerPid, _ILAlias },
        %   { create, BinDomain, CertReqOptionMap } } ->

        { createCertificateAsync,
                [ BinDomain, DNSProvider, BinEmail, Callback ] } ->
            cond_utils:if_defined( leec_debug_bot, trace_bridge:debug_fmt(
                "LEEC bot requested to create a certificate "
                "for the '~ts' domain, asynchronously with the "
                "following callback:~n  ~p.", [ BinDomain, Callback ] ) ),

            CreationOutcome = create_certificate( BinDomain, DNSProvider,
                BinEmail, LDState ),

            %trace_bridge:debug_fmt( "Async callback called "
            %   "for ~w regarding result ~p.",
            %    [ FsmPid, CreationRes ] ),

            Callback( CreationOutcome ),

            bot_main_loop( LDState );


        { createCertificateSync, [ BinDomain, DNSProvider, BinEmail ],
          CallerPid } ->
            cond_utils:if_defined( leec_debug_bot, trace_bridge:debug_fmt(
                "LEEC bot requested to create a certificate "
                "for the '~ts' domain, synchronously for caller ~w.",
                [ BinDomain, CallerPid ] ) ),

            CreationOutcome = create_certificate( BinDomain, DNSProvider,
                                                  BinEmail, LDState ),

            CallerPid ! CreationOutcome,

            bot_main_loop( LDState );


        stop ->
            trace_bridge:info( "LEEC bot has been requested to stop." );


        Unexpected ->
            trace_bridge:warning_fmt( "LEEC bot ignored the following "
                "unexpected message:~n ~p.", [ Unexpected ] ),
            bot_main_loop( LDState )

    end.



-doc """
Actual creation of the wildcard certificate.

A certificate for "MYDOMAIN" will be written under the directory specified in
the 'cert_dir_path' key, as live/MYDOMAIN/fullchain.pem. Its associated private
key will be stored in live/MYDOMAIN/privkey.pem.
""".
-spec create_certificate( bin_domain(), dns_provider(), bin_email_address(),
                          leec_dns_state() ) -> creation_outcome().
create_certificate( BinDomainName, DNSProvider, BinEmailAddress,
                    #leec_dns_state{ environment=Env,
                                     state_dir_path=BinStateDir,
                                     work_dir_path=BinWorkDir,
                                     %cert_dir_path=BinCertDir,
                                     certbot_path=BinCertbotExecPath,
                                     credentials_dir_path=BinCredDir } ) ->

    DNSProviderOpts = get_dns_provider_options( DNSProvider, BinDomainName,
                                                BinCredDir ),

    DryRunArgs = [ "--version" ],

    % No need for specific working directory, environment or port option; not
    % expected to check at this level that it is the sole certbot instance
    % running, thus not expected to fail:
    %
    case system_utils:run_executable( BinCertbotExecPath, DryRunArgs ) of

        { _DryRetCode=0, DryCmdOutput } ->
            cond_utils:if_defined( leec_debug_bot,
                trace_bridge:debug_fmt(
                    "Dry run of '~ts' succeeded (returned '~ts').",
                    [ BinCertbotExecPath, DryCmdOutput ] ),
                basic_utils:ignore_unused( DryCmdOutput ) );

        { DryRetCode, DryCmdOutput } ->
            trace_bridge:error_fmt( "Dry run for '~ts' failed: error code #~B, "
                "output: '~ts'.",
                [ BinCertbotExecPath, DryRetCode, DryCmdOutput ] )

    end,

    DirectDomainOpt = text_utils:format( "-d ~ts", [ BinDomainName ] ),

    WildcardDomainOpt = text_utils:format( "-d *.~ts", [ BinDomainName ] ),

    % As "" is not a valid argument:
    EnvOpts = case Env of

        staging ->
            [ "--staging" ];

        production ->
            []

    end,


    % Not using 'sudo -u web-srv [...]', as using the current user:
    %RunningUser = system_utils:get_user_name(),
    %  [ "-u", RunningUser, ...

    % --quiet implies --non-interactive:
    ActualArgs = [ "certonly" | EnvOpts ]
        ++ [ "--non-interactive", "--agree-tos", "--force-renewal",
             "--config-dir", BinStateDir, "--work-dir", BinWorkDir,
             "--logs-dir", BinWorkDir  ]
        ++ DNSProviderOpts
        ++ [ "--email", BinEmailAddress, DirectDomainOpt, WildcardDomainOpt ],

    cond_utils:if_defined( leec_debug_bot, trace_bridge:debug_fmt(
        "Arguments used for the actual certificate creation:~n  ~p",
        [ ActualArgs ] ) ),

    % Processes (or possibly any certbot lock file) could be checked to avoid
    % "Another instance of Certbot is already running", at least thanks to a
    % (limited) waiting.

    % May fail for various reasons, like "Error adding TXT record:
    % HTTPSConnectionPool" / "SSL: UNEXPECTED_EOF_WHILE_READING":
    %
    case system_utils:run_executable( BinCertbotExecPath, ActualArgs ) of
    % For mock-up calls:
    %case { 0, "Testing!" } of

        { _RetCode=0, CmdOutput } ->
            cond_utils:if_defined( leec_debug_bot,
                %trace_bridge:debug_fmt(
                trace_bridge:notice_fmt(
                    "Actual run of '~ts' succeeded (returned '~ts').",
                    [ BinCertbotExecPath, CmdOutput ] ),
                basic_utils:ignore_unused( CmdOutput ) ),

            ExpectedBinDir = file_utils:bin_join(
                [ BinStateDir, "live", BinDomainName ] ),

            case file_utils:is_existing_directory( ExpectedBinDir ) of

                true ->
                    BinCertFilePath =
                        file_utils:bin_join( ExpectedBinDir, "fullchain.pem" ),

                    BinPrivKeyfilePath =
                        file_utils:bin_join( ExpectedBinDir, "privkey.pem" ),

                    % Actually always symlinks:
                    case file_utils:is_existing_file_or_link(
                            BinCertFilePath ) of

                        true ->
                            case file_utils:is_existing_file_or_link(
                                    BinPrivKeyfilePath ) of

                                true ->
                                    { certificate_generation_success,
                                      BinCertFilePath, BinPrivKeyfilePath };

                                false ->
                                    { certificate_generation_failure,
                                      { no_private_key_generated,
                                        BinPrivKeyfilePath } }

                            end;

                        false ->
                            { certificate_generation_failure,
                              { no_certificate_generated, BinCertFilePath } }

                    end;

                false ->
                    { certificate_generation_failure,
                      { no_output_directory, ExpectedBinDir } }

            end;

        ErrorP={ RetCode, CmdOutput } ->
            % A cause of error could be dead *.crt (or maybe *.key) certificate
            % symlinks, or even non-existing files.
            %
            trace_bridge:error_fmt( "Actual run for '~ts' failed: "
                "error code #~B, output: '~ts'.",
                [ BinCertbotExecPath, RetCode, CmdOutput ] ),
            { certificate_generation_failure, ErrorP }

    end.




% "Static" section.


-doc """
Returns a path to the certbot executable.

Note that any plugin for a DNS provider of choice shall have been installed.

For example, on Arch Linux with the OVH DNS provider: `pacman -Sy certbot
certbot-dns-ovh`.

Throws an exception if the executable is not found.

""".
-spec get_certbot_executable_path() -> executable_path().
get_certbot_executable_path() ->
    % Typically "/usr/bin/certbot":
    case executable_utils:lookup_executable( "certbot" ) of

        false ->
            throw( certbot_executable_not_found );

        ExecPath ->
            ExecPath

    end.



-doc """
Returns suitable certbot options related to the DNS provider, for the specified
settings.
""".
-spec get_dns_provider_options( dns_provider(), bin_domain(),
                bin_directory_path() ) -> [ command_line_element() ].
get_dns_provider_options( DNSProvider, BinDomainName, BinCredDir ) ->

    CredFilePath = leec:get_credentials_path_for( DNSProvider, BinDomainName,
                                                  BinCredDir ),

    file_utils:is_existing_file_or_link( CredFilePath ) orelse
        throw( { credentials_file_not_found, CredFilePath } ),

    file_utils:is_user_readable( CredFilePath ) orelse
        throw( { credentials_file_not_readable, CredFilePath,
                 system_utils:get_user_name() } ),

    %trace_utils:debug_fmt( "Credentials file: '~ts'.", [ CredFilePath ] ),

    case DNSProvider of

        ovh ->
            % Relying on the default max propagation duration:
            [ "--dns-ovh", "--dns-ovh-credentials", CredFilePath ]

    end.
