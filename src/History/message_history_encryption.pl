/*
    Part of Logica Line

    Author: Fábio E. R. Semedo
    Git:    https://github.com/FabioSemedo
    
    MIT License
    Copyright (c) 2025  Fabio Semedo, 
                        Gabriel Carlos, 
                        Gonçalo Branquinho, 
                        Gustavo dos Santos.
    All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

    Useful Links:
    "Cryptography with Prolog" by Markus Triska (https://www.metalevel.at/prolog/cryptography).
    SWI-Prolog crypto library documentation (https://www.swi-prolog.org/pldoc/man?section=crypto).
*/

:-module(message_history_encryption,
    [password_hash_file/1,   % +FilePath
    message_enc_file/1,     % +FilePath
    message_txt_file/1,     % +FilePath

    alg_data/1,         % +AlgoEncryptDecrypt
    alg_data_hkdf/1,    % +AlgoHKDF
    alg_psw_hash/1,     % +AlgoPswHash

    store_password_hash/1,  % +Password
    verify_password/1,      % +Password
    change_password/2,      % +Password

    password_salt_to_key_iv/4,  % +Password, +Salt, -Key, -IV
    decrypt_message_history/1,  % +Password
    encrypt_message_history/1   % +Password
    ]).

:- use_module(library(crypto)).
:- use_module(library(readutil)).

/** <module> Secure file encryption and decryption

    This module implements cryptographic operations for passwordbased file encryption  
    including password hashing, authenticated encryption, and key derivation.

    ## Module Details
        - Implements AES-256-GCM authenticated encryption
        - Uses HKDF for key derivation from passwords
        - Stores salt, authentication tags and encrypted messages in the ecryption output file. (message_enc_file/1).
        - A fresh salt is generated randomly every time file is encrypted.
        - Requires OpenSSL 1.1.0+ for cryptographic operations

    ## First time use setup
        Create and verify a new password.
        Encrypt the storage file (message_enc_file/1).
        Decrypt the storage file (message_txt_file/1).
        
            Password='_42_',  
            store_password_hash(Password),  
            verify_password(Password),  
            encrypt_message_history(Password),  
            decrypt_message_history(Password)  
        
    @version 1.0.0
    @see library(crypto)
    @tbd Modularisation of filepath and algorithm definition for facts in this module. 
    @tbd Error handling.
    @tbd Removing TXT file after encryption.
*/

%% Filepath for storing a password's hash. 
% Stored hash is used to validate a password.
password_hash_file('password_hash.bin').

%% Filepath for storing encrypted message history.
%
message_enc_file('messageHistory.enc').
%% Filepath for storing plain text message history.
%
message_txt_file('messageHistory.txt').

%% Symmetric encryption algorithm
%
alg_data('aes-128-gcm').
%% HKDF hashing algorithm
%
alg_data_hkdf(sha256).
%% Password hashing algorithm
%
alg_psw_hash('pbkdf2-sha512').

alg_data_decrypt(Alg):- alg_data(Alg).
alg_data_encrypt(Alg):- alg_data(Alg).

%% store_password_hash(+Password:string)
%
%  Hashes the given password using the algorithm specified in this knowledgebase
%  and stores the hash in the password hash file.
%
%  @param Password The plaintext password to be hashed
%  @throws permission_error If unable to write to password hash file
%  @see crypto_password_hash/3
%  @see password_hash_file/1
store_password_hash(Password) :-
    alg_psw_hash(Alg),
    crypto_password_hash(Password, Hash, [algorithm(Alg)]),
    password_hash_file(Path),
    setup_call_cleanup(
        open(Path, write, Stream),
        format(Stream, '~s', [Hash]),
        close(Stream)).

%% verify_password(+Password:string)
%
%  Validates whether the given password matches the stored password hash.
%  Matching is done with crypto_password_hash/2.
%  Fails If password doesn't match stored hash
%
%  @param Password The plaintext password to verify
%  @throws existence_error If password hash file doesn't exist
%  @see crypto_password_hash/2
%  @see password_hash_file/1
verify_password(Password) :-
    password_hash_file(Path),
    read_file_to_codes(Path, HashCodes, [type(binary)]),
    atom_codes(Hash, HashCodes),
    crypto_password_hash(Password, Hash).

%% change_password(+CurrentPassword:string, +NewPassword:string)
%
%  Changes the stored password and re-encrypts message history with new password.
%  Requires the given current password to be valid.
%  Message history file must be decrypted *before* current password can be changed.
%  Note that this check is implemented in the current version.
%  Fails If current password is invalid
%
%  @param CurrentPassword The current valid password
%  @param NewPassword    The new password to set
%  @see verify_password/1
%  @see store_password_hash/1
%  @see encrypt_message_history/1
change_password(CurrPassword, NewPassword):-
    verify_password(CurrPassword),
    store_password_hash(NewPassword),
    message_txt_file(Txt),
    (exists_file(Txt) -> encrypt_message_history(NewPassword) ; false).

%% password_salt_to_key_iv(+Password:string, +Salt:list(integer), -Key:list(integer), -IV:list(integer))
%
%  Derives encryption key and initialization vector from password and salt.  
%  Uses HKDF with separate info tags for key and IV derivation.  
%  Note that the length of the derived Key and IV are set for `algorithm('aes-128-gcm')`.
%
%  @param Password The plaintext password
%  @param Salt     Salt value (16 bytes). This should be randomly generated.
%  @param Key      Output encryption key (16 bytes)
%  @param IV       Output initialization vector (12 bytes)
%  @see crypto_password_hash/3
%  @see crypto_data_hkdf/4
%  @see alg_psw_hash/1
%  @see alg_data_hkdf/1
%  @see alg_data/1
password_salt_to_key_iv(Password, Salt, Key, IV) :-
    alg_psw_hash(AlgPsw),
    crypto_password_hash(Password, Hash, [algorithm(AlgPsw), salt(Salt)]),
    
    alg_data_hkdf(AlgHkdf),
    crypto_data_hkdf(Hash, 16, Key, [info("key"),algorithm(AlgHkdf)]),
    crypto_data_hkdf(Hash, 12, IV, [info("iv"),algorithm(AlgHkdf)]).

%% decrypt_message_history(+Password:string)
%
%  Decrypts the message history file using the provided password.
%  Verifies password first and performs authenticated decryption.
%  Fails If password is incorrect or decryption fails
%
%  @param Password The decryption password
%  @throws existence_error If encrypted message file doesn't exist
%  @throws domain_error If file format is invalid
%  @see verify_password/1
%  @see password_salt_to_key_iv/4
%  @see crypto_data_decrypt/6
%  @see message_enc_file/1
%  @see message_txt_file/1
decrypt_message_history(Password) :-
    verify_password(Password),
    
    message_enc_file(InputFile),
    read_file_to_codes(InputFile, Codes, [type(binary)]),   
    
    %FileData = [16 byte Salt]+[16 byte Tag]+[rest is the encrypted chat history]
    length(SaltCodes, 16),  %needed for hkdf derivation of Key and IV
    append(SaltCodes, Rest1, Codes),
    length(TagCodes, 16),   %needed for data decrypt
    append(TagCodes, CipherCodes, Rest1),

    Salt = SaltCodes,
    Tag = TagCodes,
    
    password_salt_to_key_iv(Password, Salt, Key, IV),

    alg_data_decrypt(Alg),

    crypto_data_decrypt(CipherCodes, Alg, Key, IV, Plaintext, [tag(Tag)]),

    message_txt_file(OutputFile),
    setup_call_cleanup(
        open(OutputFile, write, Stream, [type(binary)]),
        format(Stream, '~s', [Plaintext]),
        close(Stream)
    ).


%% encrypt_message_history(+Password:string)
%
%  Encrypts the message history file using the provided password.
%  Generates new salt and uses authenticated encryption.
%  It is advisable that the given password be saved somewhere secure.
%  In current version a hash is used.
%
%  @param Password The encryption password
%  @throws existence_error If plaintext message file doesn't exist
%  @throws permission_error If unable to write encrypted file
%  @see crypto_n_random_bytes/2
%  @see password_salt_to_key_iv/4
%  @see crypto_data_encrypt/6
%  @see message_txt_file/1
%  @see message_enc_file/1
encrypt_message_history(Password) :-
    crypto_n_random_bytes(16, Salt),
    
    password_salt_to_key_iv(Password, Salt, Key, IV),
    
    message_txt_file(InputFile),
    read_file_to_codes(InputFile, Plaintext, [type(binary)]),
    
    alg_data_encrypt(Alg),
    
    crypto_data_encrypt(Plaintext, Alg, Key, IV, Ciphertext, [tag(Tag)]),

    %   [16 byte Salt][16 byte Tag][Ciphertext]
    message_enc_file(OutputFile),
    setup_call_cleanup(
        open(OutputFile, write, Stream, [type(binary)]),
        format(Stream, '~s~s~s', [Salt, Tag, Ciphertext]),
        close(Stream)
    ).