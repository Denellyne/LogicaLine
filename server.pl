:- use_module(library(socket)).

create_server(Port) :-
      tcp_socket(Socket),
      tcp_bind(Socket, Port),
      tcp_listen(Socket, 5),
      tcp_open_socket(Socket, StreamPair),
      stream_pair(StreamPair, AcceptFd, _),
      dispatch(AcceptFd,[]).

:- dynamic connections/1.

dispatch(AcceptFd,Connections) :-
        tcp_accept(AcceptFd, Socket, Peer),
        thread_create(process_client(Socket, Peer), _, [ detached(true) ]),
        writeln("New connection"),
        dispatch(AcceptFd,Connections).


process_client(Socket, _Peer) :-
    setup_call_cleanup(
        tcp_open_socket(Socket, In,Out),
        handle_client(In,Out),
        close_connection(In,Out)
    ).

close_connection(In, Out) :-
        write("Closing stream"),
        close(In, [force(true)]),
        close(Out, [force(true)]).

handle_client(In,Out) :-
  assertz(connections(Out)),
  handle_service(In,Out).

send_message_to_client(_,[]).
send_message_to_client(Input,[Out|Connections]) :- 
    copy_term(Input,String),
    writeln(Out,String),
    flush_output(Out),
    send_message_to_client(Input,Connections).
  
send_message(Input,Out) :-
  bagof(X,connections(X),Connections),
  delete(Connections,Out,ConnectionsParsed),
  send_message_to_client(Input,ConnectionsParsed).
  

handle_service(In,Out) :-
    read_line_to_string(In, Input),
    (  Input == end_of_file -> writeln("Connection dropped"),fail;
      writeln(Input),
      send_message(Input,Out),
      handle_service(In,Out)
    ).
    
