:- use_module(library(socket)).
:- use_module(library(readutil)).

setup_client(Port) :- 
  setup_call_catcher_cleanup(
    tcp_socket(Socket),
    tcp_connect(Socket, localhost:Port),
    exception(_),
    tcp_close_socket(Socket)),
    
  setup_call_cleanup(
    tcp_open_socket(Socket, In, Out),
    talk(In, Out),
    close_connection(In, Out)).

close_connection(In, Out) :-
        close(In, [force(true)]),
        close(Out, [force(true)]).

talk(In,Out) :-
    writeln("Input:"),
    read(Input),nl,
    writeln(Input),
    read(In, Int),
    (  Int == end_of_file -> writeln("Connection dropped"),fail;
      write(Out,Input),
      talk(In,Out)
    ).

