%% Copyright 2015-2021 Guillaume Bour
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


% Copyright (C) 2020-2024 Olivier Boudeville
%
% This file is part of the Ceylan-LEEC library, a fork of the Guillaume Bour's
% letsencrypt-erlang library, released under the same licence.


% @doc This module corresponds to an embedded webserver that may be used for the
% ACME http-based interactions.
%
% Note: not integrated in Ceylan-LEEC, at least currently.
%
% @hidden
%
-module(leec_elli_handler).

% Original work:
-author("Guillaume Bour (guillaume at bour dot cc)").

% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com").




%-behaviour(elli_handler).

% Apparently not necessary:
%-include_lib("elli/include/elli.hrl").

-export([ handle/2, handle_event/3 ]).


% @doc Handles specified request; returns a reply with an http code.
handle( Req, Args ) ->
	%trace_bridge:debug_fmt( "Elli: ~p~n~p", [ Req, Args ] ),
	handle( elli_request:method( Req ), elli_request:path( Req ), Req, Args ).


% (helper)
handle( 'GET', [ <<".well-known">>, <<"acme-challenge">>, Token ], Req,
		[ Thumbprints ] ) ->

	% NOTE: when testing on Travis with local boulder instance, Host header may
	% contain port number; I dunno if it can happen against production boulder,
	% but these lines filter it out:

	Header = elli_request:get_header( <<"Host">>, Req, <<>> ),

	[ Host | _Port ] = binary:split( Header, <<":">> ),

	%trace_bridge:debug_fmt( "ELLI: host=~p.", [ Host ] ),

	case maps:get( Host, Thumbprints, _Def=undefined ) of

		#{ Token := Thumbprint } ->

			%trace_bridge:debug_fmt( "Token match: ~p -> ~p.",
			%                       [ Token, Thumbprint ] ),

			{ 200, [ { <<"Content-Type">>, <<"text/plain">> } ], Thumbprint };

		Other ->
			trace_bridge:debug_fmt( "No token match: ~p -> ~p.",
									[ Token, Other ] ),

			{ 404, [], <<"Not Found">> }

	end.


% @doc Handles specified request events.
%
% Unused.
%
handle_event( _, _, _ ) ->
	ok.
