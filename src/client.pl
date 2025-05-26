:- use_module(library(socket)).
:- use_module(library(readutil)).
:- use_module(library(pcre)).


setup_client(Ip,Port):-
  setup_call_catcher_cleanup(
    tcp_socket(Socket),
    tcp_connect(Socket, Ip:Port),
    exception(_),
    tcp_close_socket(Socket)),
  
setup_call_cleanup(
    tcp_open_socket(Socket, In, Out),
    handle_connection(In, Out),
    close_connection(In, Out)).

setup_client(Port) :- 
  setup_call_catcher_cleanup(
    tcp_socket(Socket),
    tcp_connect(Socket, localhost:Port),
    exception(_),
    tcp_close_socket(Socket)),
    
  setup_call_cleanup(
    tcp_open_socket(Socket, In, Out),
    handle_connection(In, Out),
    close_connection(In, Out)).

close_connection(In, Out) :-
        close(In, [force(true)]),
        close(Out, [force(true)]).

handle_connection(In,Out) :-
  thread_create(receive_messages(In) , _ , [detached(true)]),
  send_messages(Out).

receive_messages(In) :-
    read_line_to_string(In, Input),
      (  Input == end_of_file -> writeln("Connection dropped"),fail;
        writeln(Input),
        receive_messages(In)
      ).
    

write_to_stream(Stream,String) :- 
  writeln(Stream,String),
  flush_output(Stream).

send_messages(Out) :-
    writeln("Input:"),
    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, String),
    ( String == "DISCONNECT" -> writeln("Disconnecting..."),halt();
      write_to_stream(Out,String),
      send_messages(Out)
    ).

