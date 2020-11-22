# LEEC: Let's Encrypt Erlang with Ceylan

This library is yet another fork of the Let's Encrypt client library for Erlang

It is indeed a Ceylan fork of the original and much appreciated [letsencrypt-erlang](https://github.com/gbour/letsencrypt-erlang) library whose author is Guillaume Bour.

LEEC is notably used in the context of [US-Web](http://us-web.esperide.org/).


The main differences introduced by LEEC are:
- more comments, more spell-checking, much clarification
- more typing, more runtime checking
- dependency onto [Ceylan-Myriad](https://github.com/Olivier-Boudeville/Ceylan-Myriad) added, to benefit from its facilities
- JSON parser can be JSX (the default), or Jiffy (refer to the `JSON parsers` section)
- porting done from [gen_fsm](https://erlang.org/documentation/doc-6.1/lib/stdlib-2.1/doc/html/gen_fsm.html) (soon to be deprecated) to the newer [gen_statem](https://erlang.org/doc/man/gen_statem.html)
- minor API changes, for a clearer mode of operation
- fixed the compilation with Erlang version 23.0 and higher (ex: w.r.t. to http_uri/uri_string, to updated dependencies such as Jiffy, and newer Cowboy for the examples)
- allow for *concurrent* certificate requests (ex: if managing multiple virtual hosts, all requesting new certificates at webserver start-up); so LEEC generates certificates in parallel and does not rely on a *registered* FSM anymore
- `connect_timeout` deprecated in favor of `http_timeout`


## Overview

Features:

- [x] ACME v2
- [ ] registering client (with email)
- [x] issuing RSA certificate
- [ ] revoking certificate
- [?] SAN certificate (_Subject Alternative Names_; added yet not tested yet)
- [ ] allow EC keys
- [ ] choose RSA key length
- [?] unittests (inherited from upstream, possibly still functional)
- [?] hex package (inherited from upstream, possibly still functional)

Modes
- [?] webroot (inherited from upstream, probably still functional)
- [x] slave (main use case of interest with LEEC)
- [?] based on a standalone http server (inherited from upstream, possibly still functional)

Validation challenges
- [x] http-01 (http)
- [ ] dns-01
- [ ] proof-of-possession-01

## Prerequisites
- openssl >= 1.1.1 (required to generate RSA key and certificate request)
- Erlang OTP (tested with 23.1 versions and upwards)


## Building

Two build procedures can be used from the root of LEEC:
- either a rebar3-based one: then run `make all-rebar3`, or just:
```
 $> ./rebar3 update
 $> ./rebar3 compile
```
- or one relying on Ceylan's native build system: then run `make all`


## Quickstart (as webroot)

You must execute this example on the server targeted by _mydomain.tld_.

TCP port 80 (`http`) must be opened, and a webserver listening on it (line 1) and serving `/path/to/webroot/` content shall be available.

Both `/path/to/webroot` and `/path/to/certs` must be writable by the LEEC Erlang process (at least to create respectively any `/path/to/webroot/.well-known/acme-challenge/ANY_FILE` and `/path/to/certs/ANY_FILE`).
One may use UNIX groups to isolate users and minimise assigned permissions (use `chgrp`/`chmod` for that, and `touch` to test).


```erlang

 $> $(cd /path/to/webroot && python -m SimpleHTTPServer 80)&
 $> ./rebar3 shell
 $erl> application:ensure_all_started(leec).
 $erl> {ok, FsmPid} = letsencrypt:start([{mode,webroot},{webroot_dir_path,"/path/to/webroot"},
 {cert_dir_path,"/path/to/certs"}]).
 $erl> letsencrypt:obtain_certificate_for( <<"mydomain.tld">>, FsmPid, #{async => false}).
{ok, #{cert => <<"/path/to/certs/mydomain.tld.crt">>, key => <<"/path/to/certs/mydomain.tld.key">>}}
 $erl> ^C

 $> ls -1 /path/to/certs
 letsencrypt.key
 mydomain.tld.crt
 mydomain.tld.csr
 mydomain.tld.key
```


## Mode of Operation

  The overall process is [explained here](https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.4).

  The LEEC agent gets in touch with the Let's Encrypt ACME server, authenticates itself (through a RSA key that it generated, nonces, etc.) and, based on the obtained URI directory, triggers the relevant operations on the ACME server, relying on a simple FSM (*Finite State Machine*) for that.

  During the certification process, the ACME server returns challenge(s) and then tries to query a corresponding challenge answer through a file that it is to obtain from the domain name for which a certificate is requested (typically the ACME server attempts to download such a file from a webserver running on the domain of interest).

  So LEEC (for `http-01` challenges), generates and writes such a challenge file under `/path/to/webroot` directory.

  Finally, keys and certificates are written in the `/path/to/certs` directory.



## Escript

The `bin/eletsencrypt` Escript allows the management of certificates directly from the UNIX command-line.

Its configuration is defined in `etc/eletsencrypt.yml`. It shall be run only from the root of the repository (i.e. as `bin/eletsencrypt`).

Options:
 * **-h|--help**: show help
 * **-l|--list**: list certificates informations
   * **-s|--short**: along with *-l*, display informations in short form
 * **-r|--renew**: renew expired certificates
 * **-f|--force**: along with *-r*, force certificates renewal even if not expired
 * **-c|--config CONFIG-FILE**: use *CONFIG-FILE* configuration instead of default one

Optionally, you can provide as parameter the domain you want to apply options.



## API


* `letsencrypt:start(Params)`: starts the LEEC client process, creating a corresponding FSM (as a separate process). Params is a list of parameters, chosen from the following ones:
  * `staging` (optional): uses staging API (generating fake certificates - the default behavior is to use real API)
  * `{mode, Mode}` (required): chooses the mode of operation, where `Mode` is one of: `webroot`, `slave` and `standalone`
  * `{cert_dir_path, Path}` (required): pinpoints the path where to the read and/or written certificates are stored; must be writable by the LEEC agent process if a key is to be generated
  * `{agent_key_file_path, KeyFilePath}` (optional): specifies the file containing any PEM RSA private key to reuse by the LEEC agent (otherwise a `letsencrypt-agent.key-XXX` file will be generated in the certificate directory)
  * `{http_timeout, Timeout}` (integer, optional, default to 30000 ms - i.e. 30 seconds): http queries timeout (in milliseconds)


Mode-specific parameters:
  * _webroot_ mode: `{webroot_dir_path, Path}` (required): pinpoints the directory path where to store challenge thumbprints. Must be writable by the LEEC process, and available through the root path of your webserver so that the ACME server can download these challenge answers

  * _standalone_ mode: `{port, Port}` (optional, defaults to `80`): TCP port to listen for http queries from the ACME server in the course of challenge validation

Returns: `{ok, Pid}` where Pid is the PID of the LEEC agent process.

* `letsencrypt:obtain_certificate_for(Domain, Opts) :: generates a new certificate for the considered domain name`:
  * `Domain`: domain name (type: string or binary)
  * `Opts`: is a map of options, whose keys may be:
	* `async` :: `boolean()` (optional, _true_ by default):
	* `callback` (optional, used only when _async=true_): function called once the certificate has been generated
	* `san` :: ``[binary()]`` (optional): supplementary domain names to be added to the certificate
	* `challenge` (optional): 'http-01' (default, only supported type for the time being)

  Returns:
	* in asynchronous mode, function returns `async` (certification operations are running in the background then)
	* in synchronous mode, or as asynchronous callback function parameter:
	  * `{certificate_ready, BinCertFilePath}` on success (ex: `BinCertFilePath=<<"/tmp/foobar.org.crt">>`)
	  * `{error, Message}` on error

  Examples:
	* sync mode (shell blocks for several seconds, waiting the corresponding result):
  ```erlang
	> % Success:
	> letsencrypt:obtain_certificate_for(<<"mydomain.tld">>, #{async => false}).
	{ok, #{cert => <<"/path/to/cert">>, key => <<"/path/to/key">>}}

	> % Domain tld is incorrect:
	> letsencrypt:obtain_certificate_for(<<"invalid.tld">>, #{async => false}).
	{error, <<"Error creating new authz :: Name does not end in a public suffix">>}

	> % Domain webserver does not return a challenge file (i.e. 404 error):
	> letsencrypt:obtain_certificate_for(<<"example.com">>, #{async => false}).
	{error, <<"Invalid response from http://example.com/.well-known/acme-challenge/Bt"...>>}

	> % Returned challenge is invalid:
	> letsencrypt:obtain_certificate_for(<<"example.com">>, #{async => false}).
	{error,<<"Error parsing key authorization file: Invalid key authorization: 1 parts">>}
	or
	{error,<<"Error parsing key authorization file: Invalid key authorization: malformed token">>}
	or
	{error,<<"The key authorization file from the server did not match this challenge"...>>>}
  ```

	* async mode ('async' is written immediately):
  ```erlang
	> F = fun({Status, Result}) -> io:format("completed: ~p (result= ~p)~n") end.
	> letsencrypt:obtain_certificate_for(<<"example.com">>, #{async => true, callback => F}).
	async
	>
	...
	completed: ok (result= #{cert => <<"/path/to/cert">>, key => <<"/path/to/key">>})
  ```

	* SAN:
  ```erlang
	> letsencrypt:obtain_certificate_for(<<"example.com">>, #{async => false, san => [<<"www.example.com">>]}).
	{ok, #{cert => <<"/path/to/cert">>, key => <<"/path/to/key">>}}
  ```

	* explicit `'http-01'` challenge:
  ```erlang
	> letsencrypt:obtain_certificate_for(<<"example.com">>, #{async => false, challenge => 'http-01'}).
	{ok, #{cert => <<"/path/to/cert">>, key => <<"/path/to/key">>}}
  ```


## Operation modes

### As webroot

To be used when already running a webserver (e.g. _Apache_ or _Nginx_), listening on public http port #80:

```erlang
on_complete({State, Data}) ->
	io:format("letsencrypt certicate issued: ~p (data: ~p)~n", [State, Data]),
	case State of
		ok ->
			io:format("reloading nginx...~n"),
			os:cmd("sudo systemctl reload nginx");

		_  -> pass
	end.

main() ->
	letsencrypt:start([{mode,webroot}, staging, {cert_dir_path,"/path/to/certs"}, {webroot_dir_path, "/var/www/html"]),
	letsencrypt:obtain_certificate_for(<<"mydomain.tld">>, #{callback => fun on_complete/1}),

	ok.
```

### As slave

To be used when already running an Erlang application as an http server, listening on public http port (e.g. _Cowboy_):

```erlang

on_complete({State, Data}) ->
	io:format("letsencrypt certificate issued: ~p (data: ~p)~n", [State, Data]).

main() ->
	Dispatch = cowboy_router:compile([
		{'_', [
			{<<"/.well-known/acme-challenge/:token">>, my_letsencrypt_cowboy_handler, []}
		]}
	]),
	{ok, _} = cowboy:start_http(my_http_listener, 1, [{port, 80}],
		[{env, [{dispatch, Dispatch}]}]
	),

	letsencrypt:start([{mode,slave}, staging, {cert_dir_path,"/path/to/certs"}]),
	letsencrypt:obtain_certificate_for(<<"mydomain.tld">>, #{callback => fun on_complete/1}),

	ok.
```

Here `my_letsencrypt_cowboy_handler.erl` contains the code to return the Let's Encrypt thumbprint(s) matching the received token(s):

```erlang
-module(my_letsencrypt_cowboy_handler).

-export([init/3, handle/2, terminate/3]).


init(_, Req, []) ->
	{Host,_} = cowboy_req:host(Req),

	% Notes:
	%  - cowboy_req:binding() returns undefined is token not set in URI
	%  - letsencrypt:get_challenge() returns 'error' if token+thumbprint are not available
	%
	Thumbprints = letsencrypt:get_challenge(),
	{Token,_} = cowboy_req:binding(token, Req),

	{ok, Req2} = case maps:get(Token, Thumprints, undefined) of
		Thumbprint ->
			cowboy_req:reply(200, [{<<"content-type">>, <<"text/plain">>}], Thumbprint, Req);

		_X     ->
			cowboy_req:reply(404, Req)
	end,

	{ok, Req2, no_state}.

handle(Req, State) ->
	{ok, Req, State}.

terminate(Reason, Req, State) ->
	ok.
```

### As standalone

To be used when you have no live http server running on your server.

LEEC will then start its own webserver (based on Elli) just during the time necessary in order to validate the challenge, then will stop it immediately after that.

```erlang

on_complete({State, Data}) ->
	io:format("letsencrypt certificate issued: ~p (data: ~p)~n", [State, Data]).

main() ->
	letsencrypt:start([{mode,standalone}, staging, {cert_dir_path,"/path/to/certs"}, {port, 80)]),
	letsencrypt:obtain_certificate_for(<<"mydomain.tld">>, #{callback => fun on_complete/1}),

	ok.
```


## JSON parsers

If wanting to switch from the default JSX to Jiffy, following files shall be updated:
- [rebar.config](https://github.com/Olivier-Boudeville/letsencrypt-erlang/blob/master/rebar.config)
- [src/letsencrypt.app.src](https://github.com/Olivier-Boudeville/letsencrypt-erlang/blob/master/src/letsencrypt.app.src)
(none in Myriad)


## About this LEEC fork

This is mostly a reckless fork, with so many differences (in terms of conventions, Myriad integration, whitespace cleanup) that a pull request can difficultly be considered.

By some ways, this fork is safer and more robust than the original, by others not (ex: test coverage, continuous integration). A key goal was to make it easier to understand and maintain.

In spite of the appearances, it remained nevertheless very close to the original (just differences of form, mainly).

Most of the elements of [this pull request](https://github.com/gbour/letsencrypt-erlang/pull/16/) from Marc Worrell have also been integrated.

## LEEC Website: under construction

In some unspecified future one may also be able to refer to the [LEEC official documentation](http://leec.esperide.org), otherwise to its [mirror](http://olivier-boudeville.github.io/letsencrypt-erlang/).

The 'master' branch is aimed to be the current stable version of this library.


## License

LEEC is distributed under APACHE 2.0 license, like the original work that it derives from.
