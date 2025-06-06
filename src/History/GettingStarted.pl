% Create frist password
    store_password_hash(Password).
    verify_password(Password).

%Try:
    % Encrypt message_history.txt
        encrypt_message_history(Password),
    % Decrypt message_history.txt
        decrypt_message_history(Password),

    % When we already have a password, i.e. password_hash.bin exsists and is not empty,
    %   use change_passwrod/2 instead of store_password/1. 
    %   Password change should only be made when message_history file  in decrypted
        change_passwrord(CurrPassword, NewPasswrd),

    % Check changed passwordd:
        encrypt_message_history(Password),
        decrypt_message_history(Password).