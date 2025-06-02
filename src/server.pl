:- use_module(library(socket)).
:- use_module(library(pcre)).

:- dynamic ips/1.
:- dynamic connections/1.
:- dynamic aliases/2.
:- dynamic word_map/2.
:- dynamic message_map/2.

create_server(Port) :-
      init_map,
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
  stream_property(Stream,error(Err)),
  Err == true -> close(Stream, [force(true)]),
  check_streams_errors(Streams);
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
        broadcast_notification(Notification),
        retract(connections(StreamPair)),
        retract(ips(Ip)),
        close(StreamPair, [force(true)]).

check_user_has_alias(StreamPair,Ip) :-
  stream_pair(StreamPair,In,Out),
  findall(X,aliases(Ip,X),Aliases),
  ( Aliases == [] -> 
  write_to_stream(Out,"Input the alias you wish to be called by:"),
  catch(read_line_to_string(In, Input),_, fail),
  assertz(aliases(Ip,Input)),
  assertz(ips(Ip)).

broadcast_notification(Message) :-
  findall(X,connections(X),Connections),
  send_message_to_client(Message,Connections).

keep_alive(StreamPair) :-
  sleep(15),
  write_to_stream(StreamPair,""),
  keep_alive(StreamPair).

handle_client(StreamPair,Peer) :-
  stream_pair(StreamPair,In,_),
  writeln("a"),
  set_stream(StreamPair,timeout(60)),
  writeln("a"),
  ip_name(Peer,Ip),
  writeln("a"),
  check_user_has_alias(StreamPair,Ip),
  writeln("a"),
  aliases(Ip,Alias),
  writeln("a"),
  string_concat(Alias," has joined the server", Notification),
  writeln("a"),
  broadcast_notification(Notification),
  writeln("a"),

  thread_create(keep_alive(StreamPair) , _ , [detached(true)]),
  writeln("a"),
  assertz(connections(StreamPair)),
  writeln("a"),
  string_concat(Alias,": ",Nickname),
  writeln("a"),
  handle_service(StreamPair,Nickname).

send_message_to_client(_,[]).
send_message_to_client(Input,[StreamPair|Connections]) :- 
    copy_term(Input,String),
    write_to_stream(StreamPair,String),
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

broadcast_message(Input,Alias) :-
  findall(X,connections(X),Connections),
  % delete(Connections,Out,ConnectionsParsed),
  format_string(Alias,Input,String, Timestamp),
  setup_call_cleanup(
  open("messageHistory.txt",append,Stream),
  write_to_stream(Stream,String),
  close(Stream)),

  writeln(String),
  send_message_to_client(String,Connections),
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
    
handle_service(StreamPair,Alias) :-
    stream_pair(StreamPair,In,_),
    read_line_to_string(In, Input),
    (  Input == end_of_file -> writeln("Connection dropped"),fail
       ;
       sub_string(Input,0,7, _, "/search") ->
           sub_string(Input,8,_,0, Message),
           search_message(Message, Results),
           send_message_to_client("Search results:", [StreamPair]),
           send_message_to_client_list(Results, [StreamPair]),
           handle_service(StreamPair,Alias)
       ;     
       sub_string(Input,0,6,_,"/users") ->
       send_user_list(StreamPair,"Users:"),
       handle_service(StreamPair,Alias)
       ;
       string_length(Input,0) -> handle_service(StreamPair,Alias);
       broadcast_message(Input,Alias),
       handle_service(StreamPair,Alias)
    ).
   

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
