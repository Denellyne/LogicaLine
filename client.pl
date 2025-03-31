dump_swi_homepage :-
    setup_call_cleanup(
        tcp_connect('127.0.0.1':5555, Stream, []),
        ( format(Stream,
                 'GET / HTTP/1.1~n\c
                  Host: www.swi-prolog.org~n\c
                  Connection: close~n~n', []),
          flush_output(Stream),
          copy_stream_data(Stream, current_output)
        ),
        close(Stream)).
