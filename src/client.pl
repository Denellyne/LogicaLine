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
converte_termo_para_string(StreamPair,StreamPairT),
                sub_string(StreamPairT,9,14,_,Test),
  assertz(symmetric_keys(Test, SymKey)),
  converte_termo_para_string(PubKey, PubKeyString),
  base64_encode_atom(PubKeyString, PubKeyBase64),

  stream_pair(StreamPair,_,Out),
  format(string(PubKeyMessage), "PUBLIC_KEY:~w:~w", [StreamPair,PubKeyBase64]),
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
    writeln(Input),
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
                converte_string_para_termo(PublicKey, PublickKeyTermo),
                writeln(9),
                symmetric_key(MyKey),
                writeln(10),

                rsa_public_encrypt(PublickKeyTermo, MyKey, EncryptedKey, [encoding(utf8)]),
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
            sub_string(Input, 0, 19, _, "SYMMETRIC_KEY_FROM ") ->
                writeln(16),
                sub_string(Input, 19, _, 0, Rest),
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
                sub_string(Sender_StreamPair,9,14,_,Test),
                    assertz(symmetric_keys(Test, SymmetricKey)),
                    writeln(24),
                    receive_messages(StreamPair)
                )
            ;
            sub_string(Input, 0, 8, _, "MESSAGE:") ->
                writeln(30),
                writeln(Input),
                sub_string(Input, 8, _, 0, Rest),
                split_string(Rest, ":", "", [SenderStream, EncryptedBase64, IVbase64, TagBase64]),
                base64_decode_atom(EncryptedBase64, EncryptedData),
                base64_decode_atom(IVbase64, IV),
                base64_decode_atom(TagBase64, Tag),
                string_codes(Tag, TagBytes),
                findall(symmetric_keys(X,Y),symmetric_keys(X,Y),Keys),
                
                sub_string(SenderStream,9,14,_,Test),
                writeln(Keys),
                writeln(Test),
                writeln(31),

                symmetric_keys(Test, SymmetricKey),
                crypto_data_decrypt(EncryptedData, "aes-128-gcm" , SymmetricKey, IV, Decoded, [tag(TagBytes)]),
                writeln("Mensagem Decifrada:"),
                writeln(Decoded),
                receive_messages(StreamPair)
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
      crypto_data_encrypt(Str, "aes-128-gcm" , SymmetricKey, IV, EncryptedString, [tag(Tag)]),
      base64_encode_atom(EncryptedString, EncryptedBase64),
      base64_encode_atom(IV, IVBase64), 
      base64_encode_atom(Tag, TagBase64),
      format(string(ToSend), "~w:~w:~w:~w", [StreamPair, EncryptedBase64, IVBase64, TagBase64]),
      write_to_stream(StreamPair,ToSend),
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


converte_string_para_termo(String, Term) :-
    atom_string(Atom, String),
    atom_to_term(Atom, Term, _).

converte_termo_para_string(Term, String) :-
    term_to_atom(Term, Atom),
    atom_string(Atom, String).
