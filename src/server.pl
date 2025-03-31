:- use_module(library(socket)).

create_server(Port) :-
      tcp_socket(Socket),
      tcp_bind(Socket, Port),
      tcp_listen(Socket, 5),
      tcp_open_socket(Socket, StreamPair),
      stream_pair(StreamPair, AcceptFd, _),
      dispatch(AcceptFd).



dispatch(AcceptFd) :-
        tcp_accept(AcceptFd, Socket, Peer),
        thread_create(process_client(Socket, Peer), _, [ detached(true) ]),
        dispatch(AcceptFd).


process_client(Socket, _Peer) :-
    setup_call_cleanup(
        tcp_open_socket(Socket, StreamPair),
        handle_service(StreamPair),
        close_connection(StreamPair)
    ).

close_connection(StreamPair) :-
  write("Closing stream"),
  close(StreamPair).

handle_service(StreamPair) :-
    write("Input:"),
    read_line_to_string(StreamPair, Int),
    writeln(Int),
    (  Int == end_of_file -> writeln("Connection dropped"),fail;
      handle_service(StreamPair)
    ).
    
