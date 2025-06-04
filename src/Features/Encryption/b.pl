:- use_module(library(date)).

% Get the last day of a month as a timestamp
last_day(Year, Month, Timestamp) :-
    ( Month = 12 -> 
        NextMonth = 1, NextYear is Year + 1
    ;
        NextMonth is Month + 1, NextYear = Year 
    ),
    date_time_stamp(date(NextYear, NextMonth, 1, 0, 0, 0, 0, -, -), NextStamp),
    Timestamp is NextStamp - 86400.

% Get the last Sunday of a month as a timestamp
last_sunday(Year, Month, LastSundayDate) :-
    last_day(Year, Month, LastDayStamp),
    
    %getting weekday
    stamp_date_time(LastDayStamp, LastDayDateTime, 0),
    date_time_value(date, LastDayDateTime, LastDayDate),
    day_of_the_week(LastDayDate, WeekDay),
    
    %correct to last sunday
    Offset is (WeekDay mod 7) * 86400,
    LastSundayDate is LastDayStamp - Offset,