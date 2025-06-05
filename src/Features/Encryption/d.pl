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

% =============== VERSION 2 ================================
% Encrypt a file using HKDF-derived keys and AES-256-GCM
% Usage: hkdf_encrypt_file(InputFile, OutputFile, Password)
hkdf_encrypt_file(InputFile, OutputFile, Password) :-
    % 1. Generate a random salt (recommended 16+ bytes)
    crypto_n_random_bytes(16, Salt),
    
    % 2. Derive key and IV using HKDF
    %    - Input key material (password)
    %    - Salt (random bytes)
    %    - Info (context-specific string)
    %    - Output: 44 bytes (32 for key + 12 for IV)
    crypto_data_hkdf(Password, Salt, "aes-256-gcm file encryption", 44, DerivedKeyIV),
    
    % Split into key (32 bytes) and IV (12 bytes)
    sub_atom(DerivedKeyIV, 0, 32, _, Key),
    sub_atom(DerivedKeyIV, 32, 12, _, IV),
    
    % 3. Read the plaintext file
    read_file_to_string(InputFile, Plaintext, []),
    
    % 4. Encrypt using AES-256-GCM (authenticated encryption)
    crypto_data_encrypt(Plaintext, 'aes-256-gcm', Key, IV, Ciphertext, [tag(Tag)]),
    
    % 5. Write to output file (binary format):
    %    [Salt (16)][Tag (16)][Ciphertext]
    open(OutputFile, write, Stream, [type(binary)]),
    format(Stream, '~s~s~s', [Salt, Tag, Ciphertext]),
    close(Stream).

% Decrypt a file encrypted with the above method
% Usage: hkdf_decrypt_file(InputFile, OutputFile, Password)
hkdf_decrypt_file(InputFile, OutputFile, Password) :-
    % 1. Read the encrypted file
    read_file_to_string(InputFile, AllData, []),
    
    % 2. Extract components (fixed lengths):
    %    Salt: first 16 bytes
    %    Tag: next 16 bytes
    %    Ciphertext: remaining bytes
    sub_atom(AllData, 0, 16, _, Salt),
    sub_atom(AllData, 16, 16, _, Tag),
    sub_atom(AllData, 32, _, 0, Ciphertext),
    
    % 3. Derive key and IV (same process as encryption)
    crypto_data_hkdf(Password, Salt, "aes-256-gcm file encryption", 44, DerivedKeyIV),
    sub_atom(DerivedKeyIV, 0, 32, _, Key),
    sub_atom(DerivedKeyIV, 32, 12, _, IV),
    
    % 4. Decrypt with authentication check
    crypto_data_decrypt(Ciphertext, 'aes-256-gcm', Key, IV, Plaintext, [tag(Tag)]),
    
    % 5. Write the decrypted content
    open(OutputFile, write, Stream),
    format(Stream, '~s', [Plaintext]),
    close(Stream).