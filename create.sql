PRAGMA foreign_keys = ON;

CREATE TABLE Users(
       UserID       INTEGER         PRIMARY KEY AUTOINCREMENT,
       Username     VARCHAR(20)     NOT NULL UNIQUE,
       Password     CHARACTER(256)  NOT NULL,
       Salt         CHARACTER(128)  NOT NULL,
       PrivateKeys  VARCHAR(23)     NOT NULL,
       IV           CHARACTER(24)   NOT NULL,
       MAC          CHARACTER(24)   NOT NULL,
       SignKey      CHARACTER(24)   NOT NULL,
       PubKey       CHARACTER(24)   NOT NULL);

CREATE TABLE Channels(
       ChannelID    INTEGER         PRIMARY KEY AUTOINCREMENT,
       ChannelName  VARCHAR(20)     NOT NULL,
       Description  VARCHAR(280),
       Type         CHARACTER(1)    NOT NULL CHECK(Type in ('D', 'O', 'C')) DEFAULT 'O',
       ForceJoin    BOOLEAN         NOT NULL DEFAULT FALSE);

CREATE TABLE Participants(
       ChannelID    INTEGER         NOT NULL REFERENCES Channels(ChannelID),
       UserID       INTEGER         NOT NULL REFERENCES Users(UserID),
       TimeJoined   INTEGER         NOT NULL DEFAULT CURRENT_TIMESTAMP,
       UNIQUE(ChannelID, UserID));

CREATE TABLE Messages(
       MessageID    INTEGER         PRIMARY KEY AUTOINCREMENT,
       UserID       INTEGER         NOT NULL REFERENCES Users(UserID),
       ChannelID    INTEGER         NOT NULL REFERENCES Channels(ChannelID),
       Key          INTEGER         ,
       IV           VARCHAR(1)      , -- FIXME
       Mac          VARCHAR(1)      ,
       TimeSent     INTEGER         NOT NULL DEFAULT CURRENT_TIMESTAMP,
       TimeReceived INTEGER         NOT NULL DEFAULT CURRENT_TIMESTAMP,
       Message      VARCHAR(200)    NOT NULL);

INSERT INTO Channels(ChannelName, Description, Type, ForceJoin)
VALUES ('general', 'boring stuff',         'O', TRUE),
       ('random',  'random!',              'O', TRUE),
       ('private', 'some private channel', 'C', TRUE);
