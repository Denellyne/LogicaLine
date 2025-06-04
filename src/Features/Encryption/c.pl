/*
    Files messageHistory.txt, storage_key.txt, password.txt
    DEPENDENCIES ================
    require OpenSSL 1.1.1 or greater

    ON APP START ================================
    Password <- get password from that user (should be equal to password.txt)
    
    get_storage_key(Password): 
    //Implementation 
        decrypt storage key with the given Password

    decrypt_message_history(Password):
    //Implementation
        storage key <- get_storage_key(Password)
        decrypt messageHistory.txt using the storage key
        save decrypted messageHistory.txt

    ON APP CLOSE ================================
    
    encrypt_message_history(Password):
    //Implementation
        storage key <- get_storage_key(Password)
        encrypt messageHistory.txt with storage key

    MORE ======================

    change_password(CurrPassword, NewPassword):
    //Implementation
        check CurrPassword == password from password.txt
        decrypt storage key using CurrPassword
        encrypt storage key using NewPassword
        save NewPassword to password.txt (only for demonstration)

    change_storage_key(Password, NewStorageKey):
    //Implementation
        storage key <- get_storage_key(Password)
        decrypt messageHistory with storage key
        encrypt messageHistory with NewStorageKey
        save messageHistory.txt
        encrypt NewStorageKey using Password
        save new storage key (encrypted) in storage_key.txt
    
    IMPORTANT
     Use load_private_key ?
*/

% REFERENCES  - Cryptography with Prolog by Markus Triska, https://www.metalevel.at/prolog/cryptography#passwords

:- use_module(library(crypto)).
:- use_module(library(readutil)).
:- use_module(library(filesex)).

% Constants/Facts
algorithm('pbkdf2-sha512').
password_file('password.txt').
password_hash_file('password_hash.bin').
key_file('storage_key.txt').
message_file('messageHistory.txt').

%% TODO: 
    % Define FileDoesNotExsist behaivour. May be used to reset the chatroom message history.
    % Read/write permisison checks may be used in the future.
    % Example: setup storage key's salt for
    % key_file(Path), 
    % (exists_file(Path) -> 
    %   true
    % ; 
    %   crypto_n_random_bytes(16, Salt),
    %   setup_call_cleanup(
    %   open(Path, write, Stream),
    %   format(Stream, '~w\n', [Salt]),
    %   close(Stream))
    % ).



%%  store_password_hash(+Password)
%
%   Hash given password using {@code algorithm(Alg)} specified in this knowledgebase.
%   Save hashed password to {@code password_hash_file(Path)}.
%
%   @param Password string: user given password string.
%   @see crypto_password_hash/3
store_password_hash(Password) :-
    crypto_password_hash(Password, Hash, [algorithm(Alg)]),
    password_hash_file(Path),
    setup_call_cleanup(
        open(Path, write, Stream),
        format(Stream, '~w', [Hash]),
        close(Stream)).

%%verify_password(+Password)
%
%   Validate given password.
%
%   @param Password     A user given string.
%   @see crypto_password_hash/2
verify_password(Password) :-
    password_hash_file(Path),
    read_file_to_string(Path, HashStr, []),
    atom_string(Hash, HashStr),
    (   crypto_password_hash(Password, Hash)
    ->  true % Password is ok
    ;   false % Password is not okay
    ).

% Read file into bytes
read_bytes(Path, Bytes) :-
    read_file_to_codes(Path, Codes, [type(binary)]),
    phrase(bytes(Bytes), Codes).

% Write bytes to file
write_bytes(Path, Bytes) :-
    phrase(bytes(Bytes), Codes),
    setup_call_cleanup(
        open(Path, write, Stream, [type(binary)]),
        format(Stream, '~s', [Codes]),
        close(Stream)).

% Decrypt storage key with password
get_storage_key(Password, StorageKey) :-
    key_file(Path),
    ( exists_file(Path)->
        true
    ;   
        atomics_to_string([Path, " file not found."], Str),
        write(Out, Str),
        fail
    ),
    read_bytes(Path, Encrypted),
    algorithm(Alg),
    crypto_data_decrypt(Encrypted, Alg, Password, StorageKey).

% Decrypt message history
decrypt_message_history(Password) :-
    get_storage_key(Password, Key),
    message_file(Path),
    read_bytes(Path, Encrypted),
    algorithm(Alg),
    crypto_data_decrypt(Encrypted, Alg, Key, Decrypted, []),
    message_history_file(Out),
    write_bytes(Out, Decrypted).

% Encrypt message history
encrypt_message_history(Password) :-
    get_storage_key(Password, Key),
    message_file(Path),
    read_bytes(Path, Plain),
    algorithm(Alg),
    crypto_data_encrypt(Plain, Alg, Key, Cipher, []),
    write_bytes(Path, Cipher).

% Change password
change_password(CurrPassword, NewPassword) :-
    verify_password(CurrPassword),
    get_storage_key(CurrPassword, Key),
    algorithm(Alg),
    crypto_data_encrypt(Key, Alg, NewPassword, EncryptedKey, []),
    key_file(Path),
    write_bytes(Path, EncryptedKey),
    store_password_hash(NewPassword).

% Helper: Convert between codes and bytes
bytes([])     --> [].
bytes([B|Bs]) --> [B], bytes(Bs).

% Trims whitespace from string
string_trim(S, T) :-
    split_string(S, "\s", "\s", [T|_]).
