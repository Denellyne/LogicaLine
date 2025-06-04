% Encrypt a file using AES-256-CBC
% Usage: encrypt_file(InputFile, OutputFile, Password)
encrypt_file(InputFile, OutputFile, Password) :-
    % Generate a key from the password
    crypto_password_hash(Password, Key, [algorithm(sha256), iterations(100000)]),
    
    % Read the file content
    read_file_to_string(InputFile, Data, []),
    
    % Encrypt the data
    crypto_data_encrypt(Data, 'aes-256-cbc', Key, _IV, Encrypted),
    
    % Write to output file
    open(OutputFile, write, Stream, [type(binary)]),
    format(Stream, '~s', [Encrypted]),
    close(Stream).

% Decrypt a file encrypted with the above method
% Usage: decrypt_file(InputFile, OutputFile, Password)
decrypt_file(InputFile, OutputFile, Password) :-
    % Generate the same key from password
    crypto_password_hash(Password, Key, [algorithm(sha256), iterations(100000)]),
    
    % Read encrypted content
    read_file_to_string(InputFile, Encrypted, []),
    
    % Decrypt the data
    crypto_data_decrypt(Encrypted, 'aes-256-cbc', Key, _IV, Decrypted),
    
    % Write decrypted content
    open(OutputFile, write, Stream),
    format(Stream, '~s', [Decrypted]),
    close(Stream).