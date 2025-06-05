%%  message_history_encryption.pl: Secure Stored Messages Encryption/Decryption System
%
%   This knowledgebase provides cryptographic operations for secure message storage,
%   including password hashing, authenticated encryption, and key derivation.
%
%   ## Module Details
%   - Implements AES-256-GCM authenticated encryption
%   - Uses HKDF for key derivation from passwords
%   - Stores encrypted messages with salt and authentication tags
%   - Provides password change functionality with key rotation
%
%   ## Requirements
%   - SWI-Prolog 8.2+ with crypto module
%   - OpenSSL 1.1.1+ for cryptographic operations
%
%   ## References
%   - "Cryptography with Prolog" by Markus Triska
%     (https://www.metalevel.at/prolog/cryptography)
%   - SWI-Prolog crypto library documentation
%     (https://www.swi-prolog.org/pldoc/man?section=crypto)
%
%   @author         Fábio E. R. Semedo, (https://github.com/FabioSemedo)
%   @version        1.0.0
%   @see            library(crypto)
%   @since          2025-06-05

:- use_module(library(crypto)).
:- use_module(library(readutil)).

% Constants/Facts
% TODO - Consider moving these Unifying these Facts with a seperate knowledgebase
% or .properties file for modular file names.
alg_data_encrypt('aes-256-gcm').
alg_data_hkdf(sha256).
alg_psw_hash('pbkdf2-sha512').

password_hash_file('password_hash.bin').

message_enc_file('messageHistory.enc').
message_txt_file('messageHistory.txt').

alg_data_decrypt(Alg):- alg_data_encrypt(Alg).

%% TODO: 
% Define FileDoesNotExsist behavior. May be used to reset the chatroom message history.
% Read/write permission checks may be used in the future.
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
    crypto_password_hash(Password, Hash, [algorithm(Alg)]),
    password_hash_file(Path),
    setup_call_cleanup(
        open(Path, write, Stream),
        format(Stream, '~w', [Hash]),
        close(Stream)).

%% verify_password(+Password:string)
%
%  Validates whether the given password matches the stored password hash.
%  Matching is done with crypto_password_hash/2.
%
%  @param Password The plaintext password to verify
%  @fails If password doesn't match stored hash
%  @throws existence_error If password hash file doesn't exist
%  @see crypto_password_hash/2
%  @see password_hash_file/1
verify_password(Password) :-
    password_hash_file(Path),
    read_file_to_string(Path, HashStr, []),
    atom_string(Hash, HashStr),
    (   crypto_password_hash(Password, Hash)
    ->  true % Password is ok
    ;   false % Password is not okay
    ).

%% change_password(+CurrentPassword:string, +NewPassword:string)
%
%  Changes the stored password and re-encrypts message history with new password.
%  Requires the given current password to be valid.
%  Message history file must be decrypted *before* current password can be changed.
%  Note that this check is implemented in the current version.
%
%  @param CurrentPassword The current valid password
%  @param NewPassword    The new password to set
%  @fails If current password is invalid
%  @see verify_password/1
%  @see store_password_hash/1
%  @see encrypt_message_history/1
change_password(CurrPassword, NewPassword) :-
    verify_password(CurrPassword),
    store_password_hash(NewPassword),

    % TODO check messageHistory.txt, message history must be in a decrypted state to change passwords)
    encrypt_message_history(NewPassword).

%% password_salt_to_key_iv(+Password:string, +Salt:atom, -Key:atom, -IV:atom)
%
%  Derives encryption key and initialization vector from password and salt.
%  Uses HKDF with separate info tags for key and IV derivation.
%
%  @param Password The plaintext password
%  @param Salt     Random salt value (16 bytes)
%  @param Key      Output encryption key (16 bytes)
%  @param IV       Output initialization vector (16 bytes)
%  @see crypto_password_hash/3
%  @see crypto_data_hkdf/4
%  @see alg_psw_hash/1
%  @see alg_data_hkdf/1
password_salt_to_key_iv(Password, Salt, Ks, IV) :-
    alg_psw_hash(AlgPsw),
    crypto_password_hash(Password, Hash, [algorithm(AlgPsw), cost(19), salt(Salt)]),
    
    alg_data_hkdf(AlgHkdf),
    crypto_data_hkdf(Hash, 16, Ks, [info("key"),algorithm(AlgHkdf)]),
    crypto_data_hkdf(Hash, 16, IV, [info("iv"),algorithm(AlgHkdf)]).

%% decrypt_message_history(+Password:string)
%
%  Decrypts the message history file using the provided password.
%  Verifies password first and performs authenticated decryption.
%
%  @param Password The decryption password
%  @fails If password is incorrect or decryption fails
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
    read_file_to_string(InputFile, FileData),   
    
    %FileData = [16 byte Salt]+[16 byte Tag]+[rest is the encrypted chat history]
    sub_atom(FileData, 0, 16, _, Salt), %needed for hkdf derivation of Key and IV
    sub_atom(FileData, 16, 16, _, Tag), %needed for data decrypt
    sub_atom(FileData, 32, _, _, CipherText),
    
    password_salt_to_key_iv(Password, Salt, Key, IV),

    alg_data_decrypt(Algorithm),
    crypto_data_decrypt(CipherText, Algorithm, Key, IV, Plaintext, [tag(Tag)]),

    setup_call_cleanup(
        message_txt_file(OutFile),
        open(OutFile, write, Stream),
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
    read_file_to_string(InputFile, Plaintext, []),
    
    alg_data_encrypt(Alg),
    crypto_data_encrypt(Plaintext, Alg, Key, IV, Ciphertext, [tag(Tag)]),
    
    %   [16 byte Salt][16 byte Tag][Ciphertext]
    setup_call_cleanup(
        message_enc_file(OutFile),
        open(OutputFile, write, Stream, [type(binary)]),
        format(Stream, '~s~s~s', [Salt, Tag, Ciphertext]),
        close(Stream)
    ).