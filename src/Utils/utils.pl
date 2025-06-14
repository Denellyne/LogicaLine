:- ['includes'].

format_string(Alias, Input, String, TimeStamp) :-
    get_time(TimestampCurr),
    format_time(string(Time), "%a, %d %b %Y %T ", TimestampCurr),
    TimeStamp = Time,
    string_concat(Alias, Input, String_No_Date),
    string_concat(Time, String_No_Date, String).

keep_alive(StreamPair) :-
    sleep(15),
    write_to_stream(StreamPair, ""),
    keep_alive(StreamPair).


write_to_stream(StreamPair, String) :-
    stream_pair(StreamPair, _, Out),
    writeln(Out, String),
    flush_output(Out).


converte_string_para_termo(String, Term) :-
    atom_string(Atom, String),
    atom_to_term(Atom, Term, _).

converte_termo_para_string(Term, String) :-
    term_to_atom(Term, Atom),
    atom_string(Atom, String).
