% What if the server uses a password based encryption protocol hide the chat?  
% For the sake of allowing the password on the server to be changed without forcing the saved messages to be changed we do as follows:

% We have a medium length string, a passphrase (access key), that is used to access a long string (storage key).
% We load an encrypted version of the storage-key from the server's computer storage.
% Decrypt the storage-key using an access-key (which is a passphrase that we can change periodically)
% Now having the storage-key we can use that to decrypt the chat messages.

% By never showing the storage-key to the user we key part of the system hidden.
% The idea of having this 2 step process is to allow for us to change the access-key without having to re-encrypt the entire chat history.

% When changing the access-key we do the following:
% Confirm current access-key
% Decrypt storage-key
% Provide new access-key
% Encrypt storage-key with new access-key.

% Since the user never has access to the storage-key directly, that key is not as easily compromised as the access-key.
% (Of course, we as the devs need to make a point of never showing the storage-key in a public context in our code.)

% Note that only the server's decryption functions have any access to the storage key.
% Those functions would receive the access-key from the user, decrypt the storage-key with that and then try to decrypt the chat history using the storage key.

% Imports:
% cryptography
:- use_module(library(crypto)).
:- use_module(library(readutil)).
% documentaion
:- doc_server(4000,
              [ allow('.my.org')
              ]).
:- use_module(library(pldoc/doc_library)).
:- doc_load_library.

main :-
    open('access_key.txt', read, Str),
    read_file(Str,Lines),
    close(Str),
    write(Lines), 
    nl.

read_file(Stream,[]) :- 
    at_end_of_stream(Stream).

read_file(Stream,[X|L]) :-
    \+ at_end_of_stream(Stream),
    read(Stream,X),
    read_file(Stream,L).

edge(a, b).

% Save 
save_message(FilePath, Message, Password) :-
    % Convert the password into a hash
    crypto_password_hash(Password, Hash, [algorithm(sha256)]),
    crypto_data_encrypt(Message, 'aes-256-gcm', Hash, CipherText, [tag(Tag)]),
    open(FilePath, write, Stream, [type(binary)]),
    format(Stream, '~s~s', [Tag, CipherText]),
    close(Stream).

% Load
load_chat(FilePath, Password, Message) :-
    read_file_to_codes(FilePath, Codes, [type(binary)]),
    length(Tag, 16), % GCM tag is 16 bytes
    append(Tag, CipherText, Codes),
    crypto_password_hash(Password, Hash, [algorithm(sha256)]),
    crypto_data_decrypt(CipherText, 'aes-256-gcm', Hash, Message, [tag(Tag)]).

% ?- save_encrypted_message('chat.bin', "hello world", "mypassword").
% ?- load_encrypted_message('chat.bin', "mypassword", Msg).
% Msg = "hello world".
