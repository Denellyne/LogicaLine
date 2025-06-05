:- use_module(library(socket)).
:- use_module(library(pcre)).

:- dynamic ips/1.
:- dynamic connections/1. % ip
:- dynamic aliases/2.
:- dynamic word_map/2.
:- dynamic message_map/2.
:- dynamic public_key/2.
:- dynamic symmetric_keys/3. % (StreamPair receiver, Chave simétrica, StreamPair Sender)
:- dynamic all_keys_exchanged_notified/0.
:- dynamic seen/1.

create_server(Port) :-
      % init_map,
      tcp_socket(Socket),
      tcp_bind(Socket, Port),
      tcp_listen(Socket, 5),
      tcp_open_socket(Socket, StreamPair),
      stream_pair(StreamPair, AcceptFd, _),
      writeln("Server initialized"),
      thread_create(check_streams_errors(), _, [ detached(true) ]),
      dispatch(AcceptFd,[]).

check_streams_errors([]).
check_streams_errors([Stream|Streams]) :-
  catch(write_to_stream(Stream,""),_,close(Stream,[force(true)])),
  check_streams_errors(Streams).
  

check_streams_errors() :-
  findall(X,connections(X),Streams),
  sleep(15),
  check_streams_errors(Streams),
  check_streams_errors().


init_map :-
    ( exists_file("messageHistory.txt") -> 
        open("messageHistory.txt", read, Stream),
        load_messages(Stream),
        close(Stream)
    ; true
    ).

load_messages(Stream) :-
    read_line_to_string(Stream, Line),
    ( Line == end_of_file -> true
    ; 
    parse_message(Line, Timestamp, Message),
    assertz(message_map(Timestamp, Line)),
    add_message(Message, Timestamp),
    load_messages(Stream)
    ).

parse_message(Line, Timestamp, Message) :-
    sub_string(Line, 0, 25, _, Timestamp),
    sub_string(Line, 25, _, 0, Message).

dispatch(AcceptFd,Connections) :-
        tcp_accept(AcceptFd, Socket, Peer),
        thread_create(process_client(Socket, Peer), _, [ detached(true) ]),
        writeln("New connection"),
        dispatch(AcceptFd,Connections).


process_client(Socket, Peer) :-
    setup_call_cleanup(
        tcp_open_socket(Socket,StreamPair),
        handle_client(StreamPair,Peer),
        close_connection(StreamPair,Peer)
    ).

close_connection(StreamPair,Peer) :-
        write("Closing stream"),
        ip_name(Peer,Ip),
        aliases(Ip,Alias),
        string_concat(Alias," has disconnected from the server", Notification),
        thread_create(broadcast_notification(Notification), _, [ detached(true) ]),
        retract(connections(StreamPair)),
        retract(ips(Ip)),
        close(StreamPair, [force(true)]).

check_user_has_alias(StreamPair,Ip) :-
  stream_pair(StreamPair,In,_),
  retractall(aliases(Ip,_)),
  catch(read_line_to_string(In, Input),_, fail),
  assertz(aliases(Ip,Input)),
  assertz(ips(Ip)),
  write("Alias: "),
  writeln(Input).


broadcast_notification(Message) :-
  findall(X,connections(X),Connections),
  send_message_to_client(Message,Connections).

keep_alive(StreamPair) :-
  sleep(15),
  write_to_stream(StreamPair,""),
  keep_alive(StreamPair).

 handle_client(StreamPair, Peer) :-
    stream_pair(StreamPair, In, Out),
    (   read_line_to_string(In, Input),
        sub_string(Input, 0, 11, _, "PUBLIC_KEY:") ->
            sub_string(Input, 11, _, 0, PubKeyBase64),
            base64(PubKeyBin, PubKeyBase64),
            ip_name(Peer, Ip),
            assertz(public_key(StreamPair, PubKeyBin)),
            assertz(public_key(Ip, PubKeyBin)),
            writeln("Chave pública recebida do cliente"),
            format(string(Notification), "NEW_PUBLIC_KEY ~w:~w", [StreamPair, PubKeyBase64]),
            findall(S, (connections(S), S \= StreamPair), OtherClients),
            send_message_to_client(Notification, OtherClients, StreamPair),
            assertz(seen(StreamPair)),
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


send_message_to_client(_,[], _).
send_message_to_client(Input,[StreamPair|Connections], SenderStream) :- 
    copy_term(Input,String),
    format(string(ToSend), "MESSAGE:~w:~w", [SenderStream, String]),
    write_to_stream(StreamPair,ToSend),
    send_message_to_client(Input,Connections).


send_message_to_client_list([], _).
send_message_to_client_list([Message|Rest], Clients) :-
    send_message_to_client(Message, Clients),
    send_message_to_client_list(Rest, Clients).

write_to_stream(StreamPair,String) :- 
  stream_pair(StreamPair,_,Out),
  writeln(Out,String),
  flush_output(Out).

format_string(Alias,Input,String, TimeStamp) :-
  get_time(TimestampCurr),
  format_time(string(Time),"%a, %d %b %Y %T ",TimestampCurr),
  TimeStamp = Time,
  string_concat(Alias,Input,String_No_Date),
  string_concat(Time,String_No_Date,String).


broadcast_message(Input, SenderStream) :-
  findall(X,connections(X),Connections),
  % delete(Connections,Out,ConnectionsParsed),
  % format_string(Alias,Input,String, Timestamp),
  setup_call_cleanup(
  open("messageHistory.txt",append,Stream),
  write_to_stream(Stream,Input),
  close(Stream)),

  writeln(Input),
  get_time(TimestampCurr),
  format_time(string(Time),"%a, %d %b %Y %T ",TimestampCurr),
  TimeStamp = Time,
  send_message_to_client(Input,Connections SenderStream),
  add_message(Input, Timestamp),
  assertz(message_map(Timestamp, String)).
  
concat_alias_to_string(String,[Alias|_],Str) :-
  % writeln(Alias),
  string_concat(String,Alias,StrTemp),
  string_concat(StrTemp,",",Str).

send_user_list(String,[],StreamPair) :-
  send_message_to_client(String,[StreamPair]).

send_user_list(String,[Ip|Ips],StreamPair) :-
  findall(X,aliases(Ip,X),Aliases),
  concat_alias_to_string(String,Aliases,Str),
  send_user_list(Str,Ips,StreamPair).
  

send_user_list(StreamPair,Str) :-
  findall(X,ips(X),Ips),
  send_user_list(Str,Ips,StreamPair).
    
handle_service(StreamPair) :-
    stream_pair(StreamPair,In,_),
    read_line_to_string(In, Input),
    (  Input == end_of_file -> writeln("Connection dropped"),fail
       ;
       sub_string(Input, 0, 13, _, "SYMMETRIC_KEY") ->
           sub_string(Input, 14, _, 0, Data),
           split_string(Data, ":", "", [SenderStreamPair, EncKeyBase64, ReceiverStreamPair]),
           writeln("Received symmetric key for another client"),
           assertz(symmetric_keys(ReceiverStreamPair, EncKeyBase64, SenderStreamPair)),
            (   \+ all_keys_exchanged_notified,
                all_symmetric_keys_exchanged ->
                assertz(all_keys_exchanged_notified),
                broadcast_all_users_ready()
           ; true
           ),
           handle_service(StreamPair)
           ;
               %sub_string(Input,0,7, _, "/search") ->
               %sub_string(Input,8,_,0, Message),
               %search_message(Message, Results),
               %send_message_to_client("Search results:", [StreamPair]),
               %send_message_to_client_list(Results, [StreamPair]),
               %handle_service(StreamPair);     
       sub_string(Input,0,6,_,"/users") ->
       send_user_list(StreamPair,"Users:"),
       handle_service(StreamPair)
       ;

       string_length(Input,0) -> handle_service(StreamPair);
       thread_create(broadcast_message(Input, StreamPair), _, [ detached(true) ]),
       handle_service(StreamPair)).
   

add_message(Message, Timestamp) :-
    split_string(Message, Words),
    exclude(==( ""), Words, FinalWords),
    maplist(update_word_map(Timestamp), FinalWords).

split_string(String, Words) :-
    split_string(String, " ", ".,!?:;\"'", Words). 


update_word_map(Timestamp, Word) :-
    string_lower(Word, LowerWord),
    ( word_map(LowerWord, List) ->
        (member(Timestamp, List) -> true
        ;  
         retract(word_map(LowerWord, List)),
         assertz(word_map(LowerWord, [Timestamp|List]))
        )
    ; assertz(word_map(LowerWord, [Timestamp]))
    ).


search_message(Text, Results) :-
    string_lower(Text, LowerText),
    word_map(LowerText, Timestamps),
    findall(Message, (member(Timestamp, Timestamps), message_map(Timestamp, Message)), Results).
search_message(_, []).


all_symmetric_keys_exchanged :-
    findall((X,Y), (symmetric_keys(X, _, Y), X \= Y), Result),
    length(Result, M),
    findall(Ip, aliases(Ip, _), Users),
    length(Users, N),
    N1 is (N-1)*N,
    M =:= N1.

broadcast_all_users_ready() :-
    findall(Receiver, symmetric_keys(Receiver, _, _), Receivers),
    sort(Receivers, UniqueReceivers),
    send_keys_to_all_receivers(UniqueReceivers).

send_keys_to_all_receivers([]).
send_keys_to_all_receivers([R|Rs]) :-
    findall((R, EncKey, S), symmetric_keys(R, EncKey, S), Keys),
    send_keys_list(R,Keys).

send_keys_list(_, []).
send_keys_list(R, [(R, EncKey, S)|Keys]) :-
    format(string(Msg), "SYMMETRIC_KEY_FROM ~w:~w", [S, EncKey]),
    write_to_stream(Out, Msg),
    send_keys_list(StreamPair, Keys).
