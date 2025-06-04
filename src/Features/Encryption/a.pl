:- use_module(library(crypto)).

test_two :-
    % Algorithm = 'chacha20-poly1305', Incompatible with my machinge (Windows)
    Algorithm = 'aes-256-gcm',
    crypto_n_random_bytes(32, Key),
    crypto_n_random_bytes(12, IV),
    crypto_data_encrypt("this is some input", Algorithm, Key, IV, CipherText, [tag(Tag)]),
    crypto_data_decrypt(CipherText, Algorithm, Key, IV, RecoveredText, [tag(Tag)]),
    writeln(Algorithm),
    writeln(Key),
    writeln(IV),
    writeln(CipherText),
    writeln(Tag),
    writeln(RecoveredText).
    % EXPECTED: ===========================================
    % Algorithm = 'chacha20-poly1305',
    % Key = [65, 147, 140, 197, 27, 60, 198, 50, 218|...],
    % IV = [253, 232, 174, 84, 168, 208, 218, 168, 228|...],
    % CipherText = <binary string>,
    % Tag = [248, 220, 46, 62, 255, 9, 178, 130, 250|...],
    % RecoveredText = "this is some input".

test_three :-
    %[algorithm(sha512), cost(17), salt(random_numbers)]
    crypto_password_hash('Password123', Hash),
    write(Hash).

test_zero:-
    write("Compiled well").


:- use_module(library(date)).

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


save_new_messages(FilePath, []):-
    true.

save_new_messages(FilePath, MessageList):-
    atomics_to_string(MessageList, S),
    ( exists_file(FilePath) -> 
        open(FilePath, append, S)
    ; 
        open(FilePath, write, S)
    ).

decryt_history(FilePath, Password):-


new_messages(List, Stream):-


print_to_file(FilePath, Author, Text):-
    print_line(Author, Text, Str),
    
print_line(Author, Text, Out):-
    get_time(Now),
    print_line(Now, Author, Text, Out).

print_line(TimeStamp, Author, Text, Out):-
    format_time(atom(T), '%a, %d %b %Y %T', TimeStamp),
    atomics_to_string([T," ", Author,": ", Text], Str),

read_chat_history_file(FilePath, Rows):-
    csv_read_file(FilePath, Rows, [functor(table), arity(3)]),
    maplist(assert, Rows).

main:-
    Me = 'Fabio',
    Message = "Hello Eveybody! My name is Markiplier :D.",
    print_to_file(Me, Message),