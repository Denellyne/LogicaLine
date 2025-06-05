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



:- dynamic symmetric_keys/2.      % (StreamPair, Chave simétrica)
:- dynamic public_key/1.
:- dynamic private_key/1.
:- dynamic symmetric_key/1.
:- dynamic iv/1.



format_string(Alias, Input, String, TimeStamp) :-
    get_time(TimestampCurr),
    format_time(string(Time), "%a, %d %b %Y %T ", TimestampCurr),
    TimeStamp = Time,
    string_concat(Alias, Input, String_No_Date),
    string_concat(Time, String_No_Date, String).

get_alias(Alias) :-
    writeln("Input the alias you wish to be called by:"),
    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, AliasNoFormat),
    ( string_length(AliasNoFormat, 0) -> fail;
      (AliasNoFormat == "end_of_file" -> fail;
       (AliasNoFormat == end_of_file -> fail;
        string_concat(AliasNoFormat, ": ", Alias))) ).
% string_length(AliasNoFormat,0) -> fail;

setup_client(Ip, Port, AliasNoFormat) :-
    string_concat(AliasNoFormat, ": ", Alias),
    setup_call_cleanup(
        tcp_socket(Socket),
        tcp_connect(Socket, Ip:Port),
        setup_call_cleanup(
            tcp_open_socket(Socket, StreamPair),
            handle_connection(StreamPair, Alias),
            close_connection(StreamPair))).

setup_client(Ip, Port) :-
    get_alias(Alias),
    setup_call_cleanup(
        tcp_socket(Socket),
        tcp_connect(Socket, Ip:Port),
        setup_call_cleanup(
            tcp_open_socket(Socket, StreamPair),
            handle_connection(StreamPair, Alias),
            close_connection(StreamPair))).

setup_client(Port) :-
    get_alias(Alias),
    setup_call_cleanup(
        tcp_socket(Socket),
        tcp_connect(Socket, localhost:Port),
        setup_call_cleanup(
            tcp_open_socket(Socket, StreamPair),
            handle_connection(StreamPair, Alias),
            close_connection(StreamPair))).


close_connection(StreamPair) :-
    close(StreamPair, [force(true)]).

keep_alive(StreamPair) :-
    sleep(15),
    write_to_stream(StreamPair, ""),
    keep_alive(StreamPair).


handle_connection(StreamPair, Alias) :-
    load_keys_from_python(_PrivKey, PubKey, SymKey),
    converte_termo_para_string(StreamPair, StreamPairT),
    sub_string(StreamPairT, 9, 14, _, Test),
    assertz(symmetric_keys(Test, SymKey)),
    converte_termo_para_string(PubKey, PubKeyString),
    base64_encode_atom(PubKeyString, PubKeyBase64),

    format(string(PubKeyMessage), "PUBLIC_KEY:~w:~w", [StreamPair, PubKeyBase64]),
    write_to_stream(StreamPair, PubKeyMessage),

    thread_create(receive_messages(StreamPair), _, [detached(true)]),
    thread_create(keep_alive(StreamPair), _, [detached(true)]),
    set_stream(StreamPair, timeout(60)),
    write_to_stream(StreamPair, Alias),
    send_messages(StreamPair, Alias).


receive_messages(StreamPair) :-
   
    stream_pair(StreamPair, In, _),
    
    read_line_to_string(In, Input),
   
    % writeln(Input),
    (
        Input == end_of_file ->
             fail
      ;
        string_length(Input, 0) ->
         receive_messages(StreamPair)
      ;
        (
            sub_string(Input, 0, 15, _, "NEW_PUBLIC_KEY ") ->
                
                sub_string(Input, 15, _, 0, Rest),
               
                split_string(Rest, ":", "", [Sender_StreamPair, PubKeyBase64]),
                
       

                base64_decode_atom(PubKeyBase64, PublicKey),
                converte_string_para_termo(PublicKey, PublickKeyTermo),
               
                symmetric_key(MyKey),
                    rsa_public_encrypt(PublickKeyTermo, MyKey, EncryptedKey, [encoding(utf8)]),
               
               
                base64_encode_atom(EncryptedKey, EncryptedKeyBase64),
                
                format(string(ToSend), "SYMMETRIC_KEY ~w:~w:~w", [StreamPair, EncryptedKeyBase64, Sender_StreamPair]),
                
                write_to_stream(StreamPair, ToSend),
               
                receive_messages(StreamPair)
          ;
            sub_string(Input, 0, 19, _, "SYMMETRIC_KEY_FROM ") ->
                
                sub_string(Input, 19, _, 0, Rest),
               
                split_string(Rest, ":", "", [Sender_StreamPair, EncryptedKeyBase64]),
                
                ( StreamPair = Sender_StreamPair ->
                      
                      receive_messages(StreamPair)
                ;
                  base64_decode_atom(EncryptedKeyBase64, EncryptedKey),
                  

                  private_key(PrivKey),

                  

                  rsa_private_decrypt(PrivKey, EncryptedKey, SymmetricKey, [encoding(utf8)]),
                  
                  sub_string(Sender_StreamPair, 9, 14, _, Test),
                  assertz(symmetric_keys(Test, SymmetricKey)),
                  
                  receive_messages(StreamPair));

                sub_string(Input, 0, 8, _, "MESSAGE:") ->
               
                % writeln(Input),
                sub_string(Input, 8, _, 0, Rest),
                split_string(Rest, ":", "", [SenderStream, EncryptedBase64, IVbase64, TagBase64]),
                base64_decode_atom(EncryptedBase64, EncryptedData),
                base64_decode_atom(IVbase64, IV),
                base64_decode_atom(TagBase64, Tag),
                string_codes(Tag, TagBytes),
                findall(symmetric_keys(X, Y), symmetric_keys(X, Y), Keys),

                sub_string(SenderStream, 9, 14, _, Test),
                % writeln(Keys),
                % writeln(Test),
                symmetric_keys(Test, SymmetricKey),
                crypto_data_decrypt(EncryptedData, "aes-128-gcm", SymmetricKey, IV, Decoded, [tag(TagBytes)]),
                % writeln("Mensagem Decifrada:"),
                with_output_to(string(StreamPairString), write_term(StreamPair, [quoted(false), numbervars(true)])),
                ( SenderStream == StreamPairString ->
                    format("1~w~n", [Decoded])
                ;   format("2~w~n", [Decoded])
                ), 
                receive_messages(StreamPair)
          ;
            format("3~w~n", [Input]),
            receive_messages(StreamPair)
        )
    ).

write_to_stream(StreamPair, String) :-
    % writeln(String),
    stream_pair(StreamPair, _, Out),
    writeln(Out, String),
    flush_output(Out).

send_messages(StreamPair, Alias) :-
    stream_property(StreamPair, error(Err)),
    Err == true -> fail;

    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, Str),

    ( Str == "/quit" -> writeln("Disconnecting..."), halt;
      string_length(Str, 0) -> write_to_stream(StreamPair, ""), send_messages(StreamPair, Alias);
      format_string(Alias, Str, String, _Timestamp),

      symmetric_key(SymmetricKey),
      iv(IV),
      % Str - Nao formatada , String - Formatada
      crypto_data_encrypt(Str, "aes-128-gcm", SymmetricKey, IV, EncryptedString, [tag(Tag)]),
      base64_encode_atom(EncryptedString, EncryptedBase64),
      base64_encode_atom(IV, IVBase64),
      base64_encode_atom(Tag, TagBase64),
      format(string(ToSend), "~w:~w:~w:~w", [StreamPair, EncryptedBase64, IVBase64, TagBase64]),
      write_to_stream(StreamPair, ToSend),
      send_messages(StreamPair, Alias)
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
        ( close(In), free_memory_file(MemFile), throw(E) )
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
        ( close(In), free_memory_file(MemFile), throw(E) )
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



init_map :-
    ( exists_file("messageHistory.txt") ->
          open("messageHistory.txt", read, Stream),
          load_messages(Stream),
          close(Stream)
    ; true
    ).

load_messages(Stream) :-
    read_line_to_string(Stream, Line),
    ( Line == end_of_file -> true
    ;
      parse_message(Line, Timestamp, Message),
      assertz(message_map(Timestamp, Line)),
      add_message(Message, Timestamp),
      load_messages(Stream)
    ).

parse_message(Line, Timestamp, Message) :-
    sub_string(Line, 0, 25, _, Timestamp),
    sub_string(Line, 25, _, 0, Message).


add_message(Message, Timestamp) :-
    split_string(Message, Words),
    exclude(==( "" ), Words, FinalWords),
    maplist(update_word_map(Timestamp), FinalWords).

split_string(String, Words) :-
    split_string(String, " ", ".,!?:;\"'", Words).


update_word_map(Timestamp, Word) :-
    string_lower(Word, LowerWord),
    ( word_map(LowerWord, List) ->
          (member(Timestamp, List) -> true
         ;
           retract(word_map(LowerWord, List)),
           assertz(word_map(LowerWord, [Timestamp|List]))
          )
    ; assertz(word_map(LowerWord, [Timestamp]))
    ).


search_message(Text, Results) :-
    string_lower(Text, LowerText),
    word_map(LowerText, Timestamps),
    findall(Message, (member(Timestamp, Timestamps), message_map(Timestamp, Message)), Results).
search_message(_, []).