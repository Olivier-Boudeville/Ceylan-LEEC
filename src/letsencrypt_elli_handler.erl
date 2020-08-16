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

-module(letsencrypt_elli_handler).
-behaviour(elli_handler).

-include_lib("elli/include/elli.hrl").
-export([ handle/2, handle_event/3 ]).


% Handles specified requests, returns a reply with an http code.
handle( Req, Args ) ->
	%trace_utils:debug_fmt( "Elli: ~p~n~p", [ Req, Args ] ),
	handle( elli_request:method( Req ), elli_request:path( Req ), Req, Args ).



handle( 'GET', [ <<".well-known">>, <<"acme-challenge">>, Token ], Req,
		[ Thumbprints ] ) ->

	% NOTE: when testing on Travis with local boulder instance, Host header may
	% contain port number; I dunno if it can happen against production boulder,
	% but these lines filter it out:

	Header = elli_request:get_header( <<"Host">>, Req, <<>> ),

	[ Host | _Port ] = binary:split( Header, <<":">> ),

	%trace_utils:debug_fmt( "ELLI: host=~p.", [ Host ] ),

	case maps:get( Host, Thumbprints, _Def=undefined ) of

		#{ Token := Thumbprint } ->

			%trace_utils:debug_fmt( "Token match: ~p -> ~p.",
			%                       [ Token, Thumbprint ] ),

			{ 200, [ { <<"Content-Type">>, <<"text/plain">> } ], Thumbprint };

		Other ->

			%trace_utils:debug_fmt( "No token match: ~p -> ~p.",
			%                       [ Token, Other ] ),

			{ 404, [], <<"Not Found">> }

	end.


% Handles specified request events.
%
% Unused
%
handle_event( _, _, _ ) ->
	ok.
