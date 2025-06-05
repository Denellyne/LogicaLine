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
                writeln(Sender_StreamPair),
                writeln(PubKeyBase64),
                
                base64_decode_atom(PubKeyBase64, PublicKey),

                writeln(9),
                symmetric_key(MyKey),
                writeln(10),

                rsa_public_encrypt(PublickKey, MyKey, EncryptedKey, [encoding(utf8)]),
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
                    base64_encode_atom(EncryptedKey, EncryptedKeyBase64),
                    writeln(20),
                    
                    private_key(PrivKey),

                    writeln(21),

                    rsa_private_decrypt(PrivKey, EncryptedKey, SymmetricKey, [encoding(utf8)]),
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
      % base64_encode_atom(EncryptedString, EncryptedBase64), 
      write_to_stream(StreamPair,String),
      send_messages(StreamPair,Alias)
    ).


load_keys_from_python(Priv, Pub, SymmetricKeyBin) :-

    process_create(path(python3), ['new_generate_keys.py'], [stdout(pipe(Out)), process(PID)]),
    read_stream_to_codes(Out, _Codes), 
    close(Out),
    process_wait(PID, ExitStatus),
    ( ExitStatus = exit(0) ->

        crypto_n_random_bytes(16, SymmetricKeyBin),
        crypto_n_random_bytes(12, IV),

        carregar_chaves(Priv, Pub),
        rsa_public_encrypt(Pub, "texto secreto", Encrypted, [encoding(utf8)]),
        rsa_private_decrypt(Priv, Encrypted, Decrypted, [encoding(utf8)]),

        format("Mensagem descriptografada: ~s~n", [Decrypted]),

        assertz(private_key(Priv)),
        assertz(public_key(Pub)),
        assertz(symmetric_key(SymmetricKeyBin)),
        assertz(iv(IV))
    ;
        format("Erro ao executar o script Python para gerar as chaves.~n"),
        fail
    ).
    


base64_encode_atom(Binary, Base64Atom) :-
     base64_encoded(Binary, Base64Codes, []),
    atom_codes(Base64Atom, Base64Codes).

base64_decode_atom(Base64Atom, Binary) :-
  atom_codes(Base64Atom, Base64Codes),
    base64_encoded(Binary, Base64Codes, []).

load_private_key_from_der_bytes(DERBytes, PrivateKeyTerm) :-
    % Confirma que DERBytes é lista de bytes
    is_list(DERBytes),
    forall(member(B, DERBytes), integer(B)),

    % Cria arquivo de memória para escrita
    open_memory_file(MemFile, write, Out),
    maplist(put_byte(Out), DERBytes),
    close(Out),

    % Abre para leitura em modo binário (octet)
    open_memory_file(MemFile, read, In, [encoding(octet)]),

    % Carrega chave privada do stream
    catch(
        load_private_key(In, private_key(PrivateKeyTerm), []),
        E,
        ( close(In), free_memory_file(MemFile), throw(E))
    ),

    close(In),
    free_memory_file(MemFile).


load_public_key_from_der_bytes(DERBytes, PublicKeyTerm) :-
    % Garante que DERBytes é lista de bytes (inteiros 0..255)
    is_list(DERBytes),
    forall(member(B, DERBytes), integer(B)),

    % Cria arquivo de memória para leitura binária
    open_memory_file(MemFile, write, Out),
    % Escreve bytes no arquivo de memória
    maplist(put_byte(Out), DERBytes),
    close(Out),

    % Agora abre para leitura (modo octet = binário)
    open_memory_file(MemFile, read, In, [encoding(octet)]),
    % Carrega chave pública do stream
    catch(
        load_public_key(In, public_key(PublicKeyTerm)),
        E,
        ( close(In), free_memory_file(MemFile), throw(E))
    ),
    close(In),
    free_memory_file(MemFile).



carregar_chaves(PrivKey, PubKey) :-
    open('private_key.pem', read, PrivStream, [type(binary)]),
    load_private_key(PrivStream, '', PrivKey),
    close(PrivStream),

    open('public_key.pem', read, PubStream, [type(binary)]),
    load_public_key(PubStream, PubKey),
    close(PubStream).
