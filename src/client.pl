:- use_module(library(socket)).
:- use_module(library(readutil)).
:- use_module(library(pcre)).

format_string(Alias,Input,String, TimeStamp) :-
  get_time(TimestampCurr),
  format_time(string(Time),"%a, %d %b %Y %T ",TimestampCurr),
  TimeStamp = Time,
  string_concat(Alias,Input,String_No_Date),
  string_concat(Time,String_No_Date,String).

get_alias(Alias) :-
  writeln("Input the alias you wish to be called by:"),
  current_input(Input),
  read_string(Input, "\n", "\r", _Sep, AliasNoFormat),
  ( string_length(AliasNoFormat,0) -> fail;
    (AliasNoFormat == "end_of_file" -> fail;
    (AliasNoFormat == end_of_file -> fail;
  string_concat(AliasNoFormat,": ",Alias)))).
  % string_length(AliasNoFormat,0) -> fail;

setup_client(Ip,Port) :- 
  get_alias(Alias),
  setup_call_cleanup(
    tcp_socket(Socket),
    tcp_connect(Socket, Ip:Port),
  setup_call_cleanup(
    tcp_open_socket(Socket,StreamPair),
    handle_connection(StreamPair,Alias),
    close_connection(StreamPair))).

setup_client(Port) :- 
  get_alias(Alias),
  setup_call_cleanup(
    tcp_socket(Socket),
    tcp_connect(Socket, localhost:Port),
  setup_call_cleanup(
    tcp_open_socket(Socket,StreamPair),
    handle_connection(StreamPair,Alias),
    close_connection(StreamPair))).

close_connection(StreamPair) :-
        close(StreamPair,[force(true)]).

keep_alive(StreamPair) :-
  sleep(15),
  write_to_stream(StreamPair,""),
  keep_alive(StreamPair).

handle_connection(StreamPair,Alias) :-
  stream_pair(StreamPair,In,_),
  thread_create(receive_messages(StreamPair) , _ , [detached(true)]),
  thread_create(keep_alive(StreamPair) , _ , [detached(true)]),
  set_stream(StreamPair,timeout(60)),
  write_to_stream(StreamPair,Alias),
  send_messages(StreamPair,Alias).

receive_messages(StreamPair) :-
    stream_pair(StreamPair,In,_),
    read_line_to_string(In, Input),
      (  Input == end_of_file -> writeln("Connection dropped"),fail;
       string_length(Input,0) -> receive_messages(StreamPair);
       writeln(Input),
       receive_messages(StreamPair)
      ).
    

write_to_stream(StreamPair,String) :- 
  % writeln(String),
  stream_pair(StreamPair,_,Out),
  writeln(Out,String),
  flush_output(Out).

send_messages(StreamPair,Alias) :-
    stream_property(StreamPair,error(Err)),
    Err == true -> fail;
    writeln("Input:"),
    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, Str),
    % read_line_to_string(Input, Str),
    ( Str == "/quit" -> writeln("Disconnecting..."),halt();
      string_length(Str,0) -> write_to_stream(StreamPair,""),send_messages(StreamPair,Alias);
      format_string(Alias,Str,String, Timestamp),
      write_to_stream(StreamPair,String),
      send_messages(StreamPair,Alias)
    ).

