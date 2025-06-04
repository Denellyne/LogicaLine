:- use_module(library(socket)).
:- use_module(library(readutil)).
:- use_module(library(pcre)).
:- use_module(library(process)).
:- use_module(library(http/json)).
:- use_module(library(base64)).


:- dynamic symmetric_keys/2. % (StreamPair, Chave simétrica)
:- dynamic public_key/1. 
:- dynamic private_key/1.
:- dynamic symmetric_key/1. 



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

keep_alive(StreamPair) :-
  sleep(15),
  write_to_stream(StreamPair,""),
  keep_alive(StreamPair).

handle_connection(StreamPair) :-
  load_keys_from_python(PrivKey, PubKey, SymKey),

  atom_codes(PubKey, PubKeyBase64),
  phrase(base64(PubKeyBase64), PubKeyCodes),
  stream_pair(StreamPair,_,Out),
  write_to_stream(StreamPair, "PUBLIC_KEY:"),
  write_to_stream(StreamPair, PubKeyBase64),

  stream_pair(StreamPair,In,_),
  thread_create(receive_messages(StreamPair) , _ , [detached(true)]),
  thread_create(keep_alive(StreamPair) , _ , [detached(true)]),
  set_stream(StreamPair,timeout(60)),
  send_messages(StreamPair).

receive_messages(StreamPair) :-
    stream_pair(StreamPair,In,_),
    read_line_to_string(In, Input),
      (  Input == end_of_file -> writeln("Connection dropped"),fail;
         string_length(Input,0) -> receive_messages(StreamPair);
         (   sub_string(Input, 0, 15, _, "NEW_PUBLIC_KEY ") ->
             % Extrai a parte depois da tag
             sub_string(Input, 15, _, 0, Rest),
             % Rest tem algo tipo "Alias:Base64Key"
             split_string(Rest, ":", "", [Sender_StreamPair, PubKeyBase64]),
             atom_codes(PubKeyBin, PubKeyBase64),
             phrase(base64(PubKeyBin), PubKeyCodes),
             % começo açgures aqui com o ponto 4. e mando para o server, 1 a 1, nao tendo que criar predicado
            
             symmetric_key(MyKey),
             rsa_public_encrypt(PubKeyBin, MyKey, EncryptedKey),
             atom_codes(EncryptedKey, EncryptedKeyBase64),
             phase(base64(EncryptedKeyBase64), EncryptedKeyCodes),
             format(string(ToSend), "SYMMETRIC_KEY ~w:~w:~w", [StreamPair, EncryptedKeyBase64, Sender_StreamPair]),
             write_to_stream(StreamPair, ToSend),
             receive_messages(StreamPair)
         ;  
          sub_string(Input, 0, 14, _, "SYMMETRIC_KEY ") ->
          sub_string(Input, 14, _, 0, Rest),
          split_string(Rest, ":", "", [Sender_StreamPair, EncryptedKeyBase64]),

          ( StreamPair = Sender_StreamPair ->
              receive_messages(StreamPair)
          ; 
              atom_codes(EncryptedKey, EncryptedKeyBase64),
              phrase(base64(EncryptedKey), EncryptedKeyCodes),
              private_key(PrivKey),
              rsa_private_decrypt(PrivKey, EncryptedKey, SymmetricKey),
              assertz(symmetric_keys(Sender_StreamPair, SymmetricKey)),
              format("Received symmetric key from ~w~n", [Sender_StreamPair]),
              receive_messages(StreamPair)
         )
         ;
         % Caso padrão só imprime a mensagem
         writeln(Input),
         receive_messages(StreamPair)
       )
      ).
    

write_to_stream(StreamPair,String) :- 
  stream_pair(StreamPair,_,Out),
  writeln(Out,String),
  flush_output(Out).

send_messages(StreamPair) :-
    stream_property(StreamPair,error(Err)),
    Err == true -> fail;
    writeln("Input:"),
    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, String),
    ( String == "/quit" -> writeln("Disconnecting..."),halt();
      write_to_stream(StreamPair,String),
      send_messages(StreamPair)
    ).


load_keys_from_python(PrivateKeyBin, PublicKeyBin, SymmetricKeyBin) :-
    process_create(path(python3),
                   ['generate_keys.py'],
                   [stdout(pipe(Out)), process(PID)]),
    read_stream_to_codes(Out, Codes),
    close(Out),
    process_wait(PID, ExitStatus),
    ( ExitStatus = exit(0) ->
        atom_codes(Atom, Codes),
        catch(
          atom_json_dict(Atom, Dict, []),
          E,
          (print_message(error, E), fail)
        ),
        PrivateBase64 = Dict.get(private_key),
        PublicBase64 = Dict.get(public_key),
        SymmetricBase64 = Dict.get(symmetric_key),

        % Decodificar base64 em binário
        base64(PrivateKeyBin, PrivateBase64),
        base64(PublicKeyBin, PublicBase64),
        base64(SymmetricKeyBin, SymmetricBase64)
    ; 
        format("Python script failed with status: ~w~n", [ExitStatus]),
        fail
    ).

