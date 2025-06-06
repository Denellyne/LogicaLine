:- ['./Utils/includes.pl'].
:- ['./Utils/utils.pl'].
:- ['./Encryption/encryption.pl'].


get_alias(Alias) :-
    writeln("Input the alias you wish to be called by:"),
    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, AliasNoFormat),
    ( string_length(AliasNoFormat, 0) -> fail;
      ( AliasNoFormat == "end_of_file" -> fail;
       ( AliasNoFormat == end_of_file -> fail;
         string_concat(AliasNoFormat, ": ", Alias)
       )
      ) 
    ).

setup_client(Ip, Port, AliasNoFormat) :-
    string_concat(AliasNoFormat, ": ", Alias),
    setup_call_cleanup(
        tcp_socket(Socket),
        tcp_connect(Socket, Ip:Port),
        setup_call_cleanup(
            tcp_open_socket(Socket, StreamPair),
            handle_connection(StreamPair, Alias),
            close_connection(StreamPair)
        )
    ).

setup_client(Ip, Port) :-
    get_alias(Alias),
    setup_call_cleanup(
        tcp_socket(Socket),
        tcp_connect(Socket, Ip:Port),
        setup_call_cleanup(
            tcp_open_socket(Socket, StreamPair),
            handle_connection(StreamPair, Alias),
            close_connection(StreamPair)
        )
    ).

setup_client(Port) :-
    get_alias(Alias),
    setup_call_cleanup(
        tcp_socket(Socket),
        tcp_connect(Socket, localhost:Port),
        setup_call_cleanup(
            tcp_open_socket(Socket, StreamPair),
            handle_connection(StreamPair, Alias),
            close_connection(StreamPair)
        )
    ).


close_connection(StreamPair) :-
    close(StreamPair, [force(true)]).


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
    (
        Input == end_of_file -> fail 
        ;
        string_length(Input, 0) -> receive_messages(StreamPair) 
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
          ( 
            StreamPair = Sender_StreamPair -> receive_messages(StreamPair)
            ;
            base64_decode_atom(EncryptedKeyBase64, EncryptedKey),
            private_key(PrivKey),
            rsa_private_decrypt(PrivKey, EncryptedKey, SymmetricKey, [encoding(utf8)]),     
            sub_string(Sender_StreamPair, 9, 14, _, Test),
            assertz(symmetric_keys(Test, SymmetricKey)),
            receive_messages(StreamPair)
          )
          ;
          sub_string(Input, 0, 8, _, "MESSAGE:") ->
          sub_string(Input, 8, _, 0, Rest),
          split_string(Rest, ":", "", [SenderStream, EncryptedBase64, IVbase64, TagBase64]),
          
          base64_decode_atom(EncryptedBase64, EncryptedData),
          base64_decode_atom(IVbase64, IV),
          base64_decode_atom(TagBase64, Tag),
          string_codes(Tag, TagBytes),
          
          findall(symmetric_keys(X, Y), symmetric_keys(X, Y), _),
          sub_string(SenderStream, 9, 14, _, Test),
          symmetric_keys(Test, SymmetricKey),
          crypto_data_decrypt(EncryptedData, "aes-128-gcm", SymmetricKey, IV, Decoded, [tag(TagBytes)]),
          with_output_to(string(StreamPairString), write_term(StreamPair, [quoted(false), numbervars(true)])),
          
          ( 
           SenderStream == StreamPairString ->
                format("1~w~n", [Decoded])
            ;   format("2~w~n", [Decoded])
          ), 
          receive_messages(StreamPair)
          ;
          format("3~w~n", [Input]),
          receive_messages(StreamPair)
        )
    ).


send_messages(StreamPair, Alias) :-
    stream_property(StreamPair, error(Err)),
    Err == true -> fail;

    current_input(Input),
    read_string(Input, "\n", "\r", _Sep, Str),

    ( Str == "/quit" -> writeln("Disconnecting..."), halt;
      string_length(Str, 0) -> write_to_stream(StreamPair, ""), send_messages(StreamPair, Alias);
      format_string(Alias, Str, _, _Timestamp),

      symmetric_key(SymmetricKey),
      iv(IV),
      crypto_data_encrypt(Str, "aes-128-gcm", SymmetricKey, IV, EncryptedString, [tag(Tag)]),
      base64_encode_atom(EncryptedString, EncryptedBase64),
      base64_encode_atom(IV, IVBase64),
      base64_encode_atom(Tag, TagBase64),
      
      format(string(ToSend), "~w:~w:~w:~w", [StreamPair, EncryptedBase64, IVBase64, TagBase64]),
      write_to_stream(StreamPair, ToSend),
      send_messages(StreamPair, Alias)
    ).





