:- use_module(library(socket)).
:- use_module(library(readutil)).
:- use_module(library(pcre)).
:- use_module(library(process)).
:- use_module(library(http/json)).
:- use_module(library(base64)).
:- use_module(library(lists)).
:- use_module(library(charsio)).       
:- use_module(library(apply)).         
:- use_module(library(system)).


:- dynamic symmetric_keys/2. % (StreamPair, Chave simétrica)
:- dynamic public_key/1. 
:- dynamic private_key/1.
:- dynamic symmetric_key/1. 
:- dynamic iv/1.



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
  load_keys_from_python(PrivKey, PubKey, SymKey),
  base64_encode_atom(PubKey, PubKeyBase64),
  stream_pair(StreamPair,_,Out),
  format(string(PubKeyMessage), "PUBLIC_KEY:~w", [PubKeyBase64]),
  write_to_stream(StreamPair, PubKeyMessage),

  stream_pair(StreamPair,In,_),
  thread_create(receive_messages(StreamPair) , _ , [detached(true)]),
  thread_create(keep_alive(StreamPair) , _ , [detached(true)]),
  set_stream(StreamPair,timeout(60)),
  write_to_stream(StreamPair,Alias),  
  send_messages(StreamPair,Alias).


receive_messages(StreamPair) :-
    writeln(1),
    stream_pair(StreamPair, In, _),
    writeln(2),
    read_line_to_string(In, Input),
    writeln(3),
    (
        Input == end_of_file ->
            writeln(4), fail
        ;
        string_length(Input, 0) ->
            writeln(5), receive_messages(StreamPair)
        ;
        (
            sub_string(Input, 0, 15, _, "NEW_PUBLIC_KEY ") ->
                writeln(6),
                sub_string(Input, 15, _, 0, Rest),
                writeln(7),
                split_string(Rest, ":", "", [Sender_StreamPair, PubKeyBase64]),
                writeln(8),
                base64_decode_atom(PubKeyBase64, PubKeyBin),
                writeln(9),
                symmetric_key(MyKey),
                writeln(10),
                setup_call_cleanup(
                    open_string(PubKeyBin, PubStream),
                    ( load_public_key(PubStream, PublicKey),
                      writeln(11)
                    ),
                    close(PubStream)
                ),
                rsa_public_encrypt(PublicKey, MyKey, EncryptedKey, []),
                writeln(12),
                writeln("EncryptedKey:"),
                writeln(EncryptedKey),
                (   is_list(EncryptedKey) -> writeln("EncryptedKey is a list")
                ;   atom(EncryptedKey) -> writeln("EncryptedKey is an atom")
                ;   string(EncryptedKey) -> writeln("EncryptedKey is a string")
                ;   writeln("EncryptedKey is unknown type")
                ),
                base64_encode_atom(EncryptedKey, EncryptedKeyBase64),
                writeln(13),
                format(string(ToSend), "SYMMETRIC_KEY ~w:~w:~w", [StreamPair, EncryptedKeyBase64, Sender_StreamPair]),
                writeln(14),
                write_to_stream(StreamPair, ToSend),
                writeln(15),
                receive_messages(StreamPair)
            ;
            sub_string(Input, 0, 14, _, "SYMMETRIC_KEY ") ->
                writeln(16),
                sub_string(Input, 14, _, 0, Rest),
                writeln(17),
                split_string(Rest, ":", "", [Sender_StreamPair, EncryptedKeyBase64]),
                writeln(18),
                ( StreamPair = Sender_StreamPair ->
                      writeln(19),
                      receive_messages(StreamPair)
                ;
                    base64_decode_atom(EncryptedKeyBase64, EncryptedKey),
                    writeln(20),
                    private_key(PrivKey),
                    writeln(21),
                    setup_call_cleanup(
                        open_string(PrivKey, PrivStream),
                        ( load_private_key(PrivStream, '', PrivateKey),
                          writeln(22)
                        ),
                        close(PrivStream)
                    ),
                    rsa_private_decrypt(PrivateKey, EncryptedKey, SymmetricKey, []),
                    writeln(23),
                    assertz(symmetric_keys(Sender_StreamPair, SymmetricKey)),
                    writeln(24),
                    receive_messages(StreamPair)
                )
            ;
            writeln(25),
            writeln(Input),
            receive_messages(StreamPair)
        )
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
     
    ( Str == "/quit" -> writeln("Disconnecting..."),halt();
      string_length(Str,0) -> write_to_stream(StreamPair,""),send_messages(StreamPair,Alias);
      format_string(Alias,Str,String, Timestamp),
      
      symmetric_key(SymmetricKey),
      iv(IV),
      crypto_data_encrypt(String, "aes-128-gcm" , SymmetricKey, IV, EncryptedString, []),
      
      write_to_stream(StreamPair,String),
      send_messages(StreamPair,Alias)
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
        crypto_n_random_bytes(16, SymmetricKeyBin),  
        crypto_n_random_bytes(12, IV),
        base64_decode_atom(PrivateBase64, PrivateKeyBin),
        base64_decode_atom(PublicBase64, PublicKeyBin),
        assertz(private_key(PrivateKeyBin)),
        assertz(public_key(PublicKeyBin)),
        assertz(symmetric_key(SymmetricKeyBin)),
        assertz(iv(IV))
    ;
        format("Python script failed with status: ~w~n", [ExitStatus]),
        fail
    ).


base64_encode_atom(Binary, Base64Atom) :-
     base64_encoded(Binary, Base64Codes, []),
    atom_codes(Base64Atom, Base64Codes).

base64_decode_atom(Base64Atom, Binary) :-
  atom_codes(Base64Atom, Base64Codes),
    base64_encoded(Binary, Base64Codes, []).
