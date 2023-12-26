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


% @doc This module concentrates <b>utilities transverse to LEEC</b>.
-module(leec_utils).

% Original work:
-author("Guillaume Bour (guillaume at bour dot cc)").

% This fork:
-author("Olivier Boudeville (olivier dot boudeville at esperide dot com").


-export([ b64encode/1, jsonb64encode/2, hexdigest/1, hashdigest/2 ]).


% Shorthands:

-type any_string() :: text_utils:any_string().

-type parser_state() :: json_utils:parser_state().

-type binary_b64() :: leec:binary_b64().




% @doc Encodes the specified content in b64.
-spec b64encode( any_string() ) -> binary_b64().
b64encode( X ) ->
	Base64 = base64:encode( X ),
	<< <<(encode_byte( B )):8>> || <<B:8>> <= Base64, B =/= $= >>.



% @doc Encodes the specified content first in JSON, then in b64.
-spec jsonb64encode( map(), parser_state() ) -> binary_b64().
jsonb64encode( X, ParserState ) when is_map( X ) ->

	%trace_bridge:debug_fmt( "Encoding in JSON then b64:~n  ~p", [ X ] ),
	XJson = json_utils:to_json( X, ParserState ),
	%trace_bridge:debug_fmt( "JSON result:~n~p", [ XJson ] ),

	b64encode( XJson );

jsonb64encode( X, _ParserState ) ->
	throw( { invalid_content_to_jsonb64encode, X } ).



% (helper)
-spec encode_byte( byte() ) -> byte().
encode_byte( $+ ) ->
	$-;

encode_byte( $/ ) ->
	$_;

encode_byte( B ) ->
	B.



% @doc Returns the hex digest of the specified string argument.
-spec hexdigest( any_string() ) -> binary().
hexdigest( X ) ->
	<< <<( hex( H ) ),( hex(L) )>> || <<H:4,L:4>> <= X >>.


% (helper)
hex( C ) when C < 10 ->
	$0 + C;

hex( C ) ->
	$a + C - 10.



% @doc Returns the SHA256 hexadecimal digest of the specified content.
-spec hashdigest( sha256, binary() ) -> binary().
hashdigest( sha256, Content ) ->
	hexdigest( crypto:hash( sha256, Content ) ).
