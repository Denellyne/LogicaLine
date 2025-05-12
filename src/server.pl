:- use_module(library(socket)).

create_server(Port) :-
      tcp_socket(Socket),
      tcp_bind(Socket, Port),
      tcp_listen(Socket, 5),
      tcp_open_socket(Socket, StreamPair),
      stream_pair(StreamPair, AcceptFd, _),
      dispatch(AcceptFd,[]).

:- dynamic connections/1.
:- dynamic aliases/2.

dispatch(AcceptFd,Connections) :-
        tcp_accept(AcceptFd, Socket, Peer),
        thread_create(process_client(Socket, Peer), _, [ detached(true) ]),
        writeln("New connection"),
        dispatch(AcceptFd,Connections).


process_client(Socket, Peer) :-
    setup_call_cleanup(
        tcp_open_socket(Socket,In,Out),
        handle_client(In,Out,Peer),
        close_connection(In,Out)
    ).

close_connection(In, Out) :-
        write("Closing stream"),
        retract(connections(Out)),
        close(In, [force(true)]),
        close(Out, [force(true)]).


handle_client(In,Out,Peer) :-
  ip_name(Peer,Ip),
  findall(X,aliases(Ip,X),Aliases),
  ( Aliases == [] -> 
  writeln(Out,"Input the alias from which you wish to be called by:"),
  flush_output(Out),
  set_stream(In,timeout(60)),
  catch(read_line_to_string(In, Input),_, fail),
  set_stream(In,timeout(infinite)),
  assertz(aliases(Ip,Input));true),
  
  aliases(Ip,Alias),
  assertz(connections(Out)),
  string_concat(Alias,": ",Nickname),
  handle_service(In,Out,Nickname).

send_message_to_client(_,[]).
send_message_to_client(Input,[Out|Connections]) :- 
    copy_term(Input,String),
    writeln(Out,String),
    flush_output(Out),
    send_message_to_client(Input,Connections).
  
send_message(Input,Out,Alias) :-
  bagof(X,connections(X),Connections),
  delete(Connections,Out,ConnectionsParsed),

  string_concat(Alias,Input,String),
  send_message_to_client(String,ConnectionsParsed).
  

handle_service(In,Out,Alias) :-
    read_line_to_string(In, Input),
    (  Input == end_of_file -> writeln("Connection dropped"),fail;
      writeln(Input),
      send_message(Input,Out,Alias),
      handle_service(In,Out,Alias)
    ).
    
