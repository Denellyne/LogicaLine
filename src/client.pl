:- use_module(library(socket)).
:- use_module(library(readutil)).
:- use_module(library(pcre)).



setup_client(Ip,Port) :- 
  setup_call_cleanup(
    tcp_socket(Socket),
    tcp_connect(Socket, Ip:Port),
  setup_call_cleanup(
    tcp_open_socket(Socket,StreamPair),
    handle_connection(StreamPair),
    close_connection(StreamPair))).

setup_client(Port) :- 
  setup_call_cleanup(
    tcp_socket(Socket),
    tcp_connect(Socket, localhost:Port),
  setup_call_cleanup(
    tcp_open_socket(Socket,StreamPair),
    handle_connection(StreamPair),
    close_connection(StreamPair))).

close_connection(StreamPair) :-
        close(StreamPair,[force(true)]).

handle_connection(StreamPair) :-
  thread_create(receive_messages(StreamPair) , _ , [detached(true)]),
  send_messages(StreamPair).

receive_messages(StreamPair) :-
    stream_pair(StreamPair,In,_),
    read_line_to_string(In, Input),
      (  Input == end_of_file -> writeln("Connection dropped"),fail;
        writeln(Input),
        receive_messages(In)
      ).
    

write_to_stream(StreamPair,String) :- 
  stream_pair(StreamPair,_,Out),
  writeln(Out,String),
  flush_output(Out).

send_messages(StreamPair) :-
    writeln("Input:"),
    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, String),
    ( String == "/quit" -> writeln("Disconnecting..."),halt();
      write_to_stream(StreamPair,String),
      send_messages(StreamPair)
    ).

