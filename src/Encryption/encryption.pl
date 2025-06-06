:- ['../Utils/includes.pl'].

:- dynamic symmetric_keys/2.      % (StreamPair, Chave simétrica)
:- dynamic public_key/1.
:- dynamic private_key/1.
:- dynamic symmetric_key/1.
:- dynamic iv/1.

load_keys_from_python(Priv, Pub, SymmetricKeyBin) :-
    process_create(path(python3), ['./Encryption/new_generate_keys.py'], [stdout(pipe(Out)), process(PID)]),
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
    is_list(DERBytes),
    forall(member(B, DERBytes), integer(B)),
    open_memory_file(MemFile, write, Out),
    maplist(put_byte(Out), DERBytes),
    close(Out),
    open_memory_file(MemFile, read, In, [encoding(octet)]),
    catch(
        load_private_key(In, private_key(PrivateKeyTerm), []),
        E,
        ( close(In), free_memory_file(MemFile), throw(E) )
    ),
    close(In),
    free_memory_file(MemFile).

load_public_key_from_der_bytes(DERBytes, PublicKeyTerm) :-
    is_list(DERBytes),
    forall(member(B, DERBytes), integer(B)),
    open_memory_file(MemFile, write, Out),
    maplist(put_byte(Out), DERBytes),
    close(Out),
    open_memory_file(MemFile, read, In, [encoding(octet)]),
    catch(
        load_public_key(In, public_key(PublicKeyTerm)),
        E,
        ( close(In), free_memory_file(MemFile), throw(E) )
    ),
    close(In),
    free_memory_file(MemFile).

carregar_chaves(PrivKey, PubKey) :-
    open('./private_key.pem', read, PrivStream, [type(binary)]),
    load_private_key(PrivStream, '', PrivKey),
    close(PrivStream),

    open('./public_key.pem', read, PubStream, [type(binary)]),
    load_public_key(PubStream, PubKey),
    close(PubStream).
