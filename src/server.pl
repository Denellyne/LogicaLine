:- use_module(library(socket)).
:- use_module(library(pcre)).
:- ['./Utils/utils.pl'].

:- dynamic ips/1.
:- dynamic connections/1. % ip
:- dynamic aliases/2.
:- dynamic word_map/2.
:- dynamic message_map/2.
:- dynamic public_key/2.
:- dynamic symmetric_keys/3. % (StreamPair receiver, Chave simétrica, StreamPair Sender)
:- dynamic get_stream/2.

create_server(Port) :-
    tcp_socket(Socket),
    tcp_bind(Socket, Port),
    tcp_listen(Socket, 5),
    tcp_open_socket(Socket, StreamPair),
    stream_pair(StreamPair, AcceptFd, _),
    writeln("Server initialized"),
    thread_create(check_streams_errors, _, [ detached(true) ]),
    dispatch(AcceptFd, []).

check_streams_errors([]).
check_streams_errors([Stream|Streams]) :-
    catch(write_to_stream(Stream, ""), _, close(Stream, [force(true)])),
    check_streams_errors(Streams).


check_streams_errors :-
    findall(X, connections(X), Streams),
    sleep(15),
    check_streams_errors(Streams),
    check_streams_errors.

parse_message(Line, Timestamp, Message) :-
    sub_string(Line, 0, 25, _, Timestamp),
    sub_string(Line, 25, _, 0, Message).

dispatch(AcceptFd, Connections) :-
    tcp_accept(AcceptFd, Socket, Peer),
    thread_create(process_client(Socket, Peer), _, [ detached(true) ]),
    writeln("New connection"),
    dispatch(AcceptFd, Connections).


process_client(Socket, Peer) :-
    setup_call_cleanup(
    tcp_open_socket(Socket, StreamPair),
    handle_client(StreamPair, Peer),
    close_connection(StreamPair, Peer)
).

close_connection(StreamPair, Peer) :-
    write("Closing stream"),
    ip_name(Peer, Ip),
    aliases(Ip, Alias),
    string_concat(Alias, " has disconnected from the server", Notification),
    thread_create(broadcast_notification(Notification), _, [ detached(true) ]),
    get_stream(Sender_StreamPair, StreamPair),
    retractall(public_key(Sender_StreamPair, _)),
    retractall(symmetric_keys(Sender_StreamPair, _, _)),
    retractall(symmetric_keys(_, _, Sender_StreamPair)),
    retract(aliases(Ip,Alias)),
    retract(ips(Ip)),
    retract(get_stream(Sender_StreamPair, StreamPair)),
    retract(connections(StreamPair)),
    close(StreamPair, [force(true)]).

check_user_has_alias(StreamPair, Ip) :-
    stream_pair(StreamPair, In, _),
    retractall(aliases(Ip, _)),
    catch(read_line_to_string(In, Input), _, fail),
    assertz(aliases(Ip, Input)),
    assertz(ips(Ip)),
    write("Alias: "),
    writeln(Input).


broadcast_notification(Message) :-
    findall(X, connections(X), Connections),
    send_message_to_client(Message, Connections, []).


handle_client(StreamPair, Peer) :-
    stream_pair(StreamPair, In, _Out),
    (   read_line_to_string(In, Input),
        writeln("Received input:"),
        sub_string(Input, 0, 11, _, "PUBLIC_KEY:") ->
        writeln("Received public key from client"),
        sub_string(Input, 11, _, 0, Rest),
        split_string(Rest, ":", "", [Sender_StreamPair, PubKeyBase64]),
        assertz(get_stream(Sender_StreamPair, StreamPair)),
        base64_decode_atom(PubKeyBase64, PubKeyBin),
        ip_name(Peer, Ip),
        format(string(Notification), "NEW_PUBLIC_KEY ~w:~w", [Sender_StreamPair, PubKeyBase64]),
        findall(S, connections(S), OtherClientsTemp),
        delete(OtherClientsTemp, StreamPair, OtherClients),
        send_message_to_client(Notification, OtherClients, []),
        assertz(public_key(Sender_StreamPair, PubKeyBin)),
        enviar_chaves_publicas(StreamPair),
        writeln("Set Stream Timeout"),
        set_stream(StreamPair, timeout(60)),
        writeln("Get Ip"),
        ip_name(Peer, Ip),
        writeln("Check user has Alias"),
        check_user_has_alias(StreamPair, Ip),
        aliases(Ip, Alias),
        writeln("Send User has joined"),
        string_concat(Alias, " has joined the server", Notification2),
        thread_create(broadcast_notification(Notification2), _, [detached(true)]),
        writeln("Start Keep Alive thread"),
        thread_create(keep_alive(StreamPair), _, [detached(true)]),
        assertz(connections(StreamPair)),
        writeln("Handle Client"),
        handle_service(StreamPair)
    ;   writeln("Cliente desconectado antes de enviar chave pública"), fail
    ).

send_message_to_client(_, [], _) :- !.
send_message_to_client(Input, [StreamPair  |Connections], SenderStream) :-
    copy_term(Input, String),
    (
    SenderStream == [] -> ToSend = String 
    ;
    format(string(ToSend), "MESSAGE:~w", [String])
    ),
    write_to_stream(StreamPair, ToSend),
    send_message_to_client(Input, Connections, SenderStream).


send_message_to_client_list([], _).
send_message_to_client_list([Message|Rest], Clients) :-
    send_message_to_client(Message, Clients),
    send_message_to_client_list(Rest, Clients).

broadcast_message(Input, SenderStream) :-
    findall(X, connections(X), Connections),
    % delete(Connections,Out,ConnectionsParsed),
    setup_call_cleanup(
    open("messageHistory.txt", append, Stream),
    write_to_stream(Stream, Input),
    close(Stream)),
    send_message_to_client(Input, Connections, SenderStream).

concat_alias_to_string(String, [Alias|_], Str) :-
    string_concat(String, Alias, StrTemp),
    string_concat(StrTemp, ",", Str).

send_user_list(String, [], StreamPair) :-
    send_message_to_client(String, [StreamPair], []).

send_user_list(String, [Ip|Ips], StreamPair) :-
    findall(X, aliases(Ip, X), Aliases),
    concat_alias_to_string(String, Aliases, Str),
    send_user_list(Str, Ips, StreamPair).


send_user_list(StreamPair, Str) :-
    findall(X, ips(X), Ips),
    send_user_list(Str, Ips, StreamPair).

handle_service(StreamPair) :-
    stream_pair(StreamPair, In, _),
    read_line_to_string(In, Input),
    (  Input == end_of_file -> writeln("Connection dropped"), fail
    ;
        sub_string(Input, 0, 14, _, "SYMMETRIC_KEY ") ->
        sub_string(Input, 14, _, 0, Data),
        split_string(Data, ":", "", [SenderStreamPair, EncKeyBase64, ReceiverStreamPair]),
        base64_decode_atom(EncKeyBase64, EncKeyBin),
        writeln("Received symmetric key for another client"),
        assertz(symmetric_keys(ReceiverStreamPair, EncKeyBin, SenderStreamPair)),
        assertz(get_stream(ReceiverStreamPair, StreamPair)),
        broadcast_all_users_ready,
        handle_service(StreamPair)
    ;     
        sub_string(Input, 0, 6, _, "/users") ->
        send_user_list(StreamPair, "Users:"),
        handle_service(StreamPair)
    ;
        string_length(Input, 0) -> handle_service(StreamPair);
        thread_create(broadcast_message(Input, StreamPair), _, [ detached(true) ]),
        handle_service(StreamPair)  ).


split_string(String, Words) :-
    split_string(String, " ", ".,!?:;\"'", Words).

broadcast_all_users_ready :-
    findall(Receiver, symmetric_keys(Receiver, _, _), Receivers),
    sort(Receivers, UniqueReceivers),
    send_keys_to_all_receivers(UniqueReceivers).

send_keys_to_all_receivers([]).
send_keys_to_all_receivers([R|Rs]) :-
    findall((R, EncKey, S), symmetric_keys(R, EncKey, S), Keys),
    send_keys_list(R, Keys),
    send_keys_to_all_receivers(Rs).

send_keys_list(_, []).
send_keys_list(R, [(R, EncKey, S)|Keys]) :-
    base64_encode_atom(EncKey, EncKeyBase64),
    format(string(Msg), "SYMMETRIC_KEY_FROM ~w:~w", [S, EncKeyBase64]),
    (   get_stream(R, RealStream) ->
        write_to_stream(RealStream, Msg)
    ;  true 
    ),
    send_keys_list(R, Keys).

base64_encode_atom(Binary, Base64Atom) :-
    base64_encoded(Binary, Base64Codes, []),
    atom_codes(Base64Atom, Base64Codes).

base64_decode_atom(Base64Atom, Binary) :-
    atom_codes(Base64Atom, Base64Codes),
    base64_encoded(Binary, Base64Codes, []).

enviar_chaves_publicas(R) :-
    findall((StreamPair, PubKey), (public_key(StreamPair, PubKey), StreamPair \= R), Pairs),
    send_public_keys(Pairs, R).

send_public_keys([], _).
send_public_keys([(StreamPair, PubKey)|Pairs], R) :-
    base64_encode_atom(PubKey, PubKeyBase64),
    format(string(Notification), "NEW_PUBLIC_KEY ~w:~w", [StreamPair, PubKeyBase64]),
    write_to_stream(R, Notification),
    send_public_keys(Pairs, R).
