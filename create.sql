PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS Users(
       UserID       INTEGER         PRIMARY KEY AUTOINCREMENT,
       Username     VARCHAR(20)     NOT NULL UNIQUE,
       Password     CHARACTER(256)  NOT NULL,
       Salt         CHARACTER(128)  NOT NULL,
       IV           CHARACTER(24)   NOT NULL,
       Pubkey       CHARACTER(128)  NOT NULL,
       Privkey      CHARACTER(2466) NOT NULL);

CREATE TABLE IF NOT EXISTS Channels(
       ChannelID    INTEGER         PRIMARY KEY AUTOINCREMENT,
       ChannelName  VARCHAR(20)     NOT NULL,
       Description  VARCHAR(280),
       Leader       INTEGER         NOT NULL REFERENCES Users(UserID),
       Type         CHARACTER(1)    NOT NULL CHECK(Type in ('D', 'O', 'C')) DEFAULT 'O');

CREATE TABLE IF NOT EXISTS Participants(
       ChannelID    INTEGER         NOT NULL REFERENCES Channels(ChannelID),
       UserID       INTEGER         NOT NULL REFERENCES Users(UserID),
       TimeJoined   INTEGER,
       UNIQUE(ChannelID, UserID));

CREATE TABLE IF NOT EXISTS Messages(
       MessageID    INTEGER         PRIMARY KEY AUTOINCREMENT,
       UserID       INTEGER         NOT NULL REFERENCES Users(UserID),
       ChannelID    INTEGER         NOT NULL REFERENCES Channels(ChannelID),
       TimeSent     INTEGER         NOT NULL,
       Message      BLOB            NOT NULL);
