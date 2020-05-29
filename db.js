var sqlite3 = require('sqlite3').verbose();
var sqlite = require('sqlite');

var database;

module.exports = {
  openDatabase: async () => {
    const db = await sqlite.open({
      filename: 'db.db',
      driver: sqlite3.Database
    });
    database = db;
    db.configure("busyTimeout", 2000);
    return database.run("PRAGMA foreign_keys = ON;");
  },

  closeDatabase: async () => database.close(),

  /* User */
  addUser: async (username, password, salt, iv, pubkey, privkey) => {
    var created = await database.run("INSERT INTO Users(Username, Password, Salt, IV, Pubkey, Privkey)\
      VALUES (?, ?, ?, ?, ?, ?);", username, password, salt, iv, JSON.stringify(pubkey), privkey);
    await database.run("INSERT INTO Participants(ChannelID, UserID) SELECT ChannelID, ? FROM Channels WHERE ForceJoin = 1;", created.lastID);
    return created;
  },

  getUserByName: async (username) => {
    return database.get("SELECT * FROM Users WHERE Username = ?;", username);
  },

  getUserById: async (uid) => {
    return database.get("SELECT * FROM Users WHERE UserID = ?;", uid);
  },

  getUsers: async (username) => {
    return database.all("SELECT * FROM Users;");
  },

  /* Channels */
  addChannel: async (name, description, type, force) => {
    return database.run("INSERT INTO Channels(ChannelName, Description, Type, ForceJoin)\
      VALUES (?, ?, ?, ?);", name, description, type, force);
  },

  getPublicChannels: async () => {
    return database.all("SELECT * FROM Channels WHERE Type = 'O';");
  },

  getDirectChannel: async (user1, user2) => {
    return database.get("SELECT ChannelID FROM Participants WHERE UserID IN (?, ?)\
      AND ChannelID IN (SELECT c.ChannelID FROM Channels c WHERE Type = 'D') GROUP BY ChannelID HAVING COUNT(*) = 2;", user1, user2);
  },

  getChannelsByUser: async (userid) => {
    return database.all("SELECT Channels.* FROM Channels INNER JOIN Participants\
      ON Channels.ChannelID = Participants.ChannelID WHERE Participants.UserID = ?", userid);
  },

  getChannel: async (channelid) => {
    return database.get("SELECT * FROM Channels WHERE ChannelID = ?;", channelid);
  },

  /* Participants */
  addParticipant: async (roomid, userid) => {
    return database.run("INSERT INTO Participants(ChannelID, UserID) VALUES (?, ?);", roomid, userid);
  },

  removeParticipant: async (roomid, userid) => {
    return database.run("DELETE FROM Participants WHERE ChannelID = ? AND UserID = ?;", roomid, userid);
  },

  getParticipantsByChannel: async (roomid) => {
    return database.all("SELECT UserID, TimeJoined from Participants WHERE ChannelID = ?;", roomid);
  },

  isParticipantInChannel: async (userid, channelid) => {
    return database.get("SELECT * FROM Participants WHERE UserID = ? AND ChannelID = ?;", userid, channelid);
  },

  /* Messages */
  addMessage: async (userid, channelid, message) => {
    return database.run("INSERT INTO Messages(UserID, ChannelID, Message) VALUES (?, ?, ?);", userid, channelid, message);
  },

  getChannelMessagesForUser: async (channelid, userid) => {
    return database.all("SELECT * FROM Messages WHERE ChannelID = ? AND \
      TimeSent > (SELECT TimeJoined FROM Participants WHERE UserID = ?);", channelid, userid);
  }
}
