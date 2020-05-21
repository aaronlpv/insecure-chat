var sqlite3 = require('sqlite3').verbose();
var sqlite = require('sqlite');

var database;

var room_types = {
  public: "O",
  private: "C",
  direct: "D"
};

module.exports = {
  openDatabase: () => {
    return sqlite.open({
      filename: 'db.db',
      driver: sqlite3.Database
    }).then((db) => { database = db; db.configure("busyTimeout", 2000); })
    .then(() => database.run("PRAGMA foreign_keys = ON;"));
  },

  closeDatabase: async () => {
    return database.close();
  },

  getUserByName: async (username) => {
    return database.get("SELECT * FROM Users WHERE Username = ?;", username);
  },

  addUser: async (username, password, salt, iv, pubkey, privkey) => {
    return database.run("INSERT INTO Users(Username, Password, Salt, IV, Pubkey, Privkey)\
      VALUES (?, ?, ?, ?, ?, ?);", username, password, salt, iv, JSON.stringify(pubkey), privkey);
  },

  addChannel: async (name, description, type, force) => {
    return database.run("INSERT INTO Channels(ChannelName, Description, Type, ForceJoin)\
      VALUES (?, ?, ?, ?);", name, description, room_types[type], force);
  },

  getPublicChannels: async () => {
    return database.all("SELECT * FROM Channels WHERE Type = 'O';");
  },

  getDirectChannel: async (user1, user2) => {
    // TODO
  },

  addParticipant: async (roomid, userid) => {
    return database.run("INSERT INTO Participants(ChannelID, UserID)\
      VALUES (?, ?);", roomid, userid);
  },

  removeParticipant: async (roomid, userid) => {
    return database.run("DELETE FROM Participants WHERE ChannelID = ? AND UserID = ?;", 
      roomid, userid);
  },

  addMessage: async (userid, channelid, message) => {
    return database.run("INSERT INTO Messages(UserID, ChannelID, Message)\
      VALUES (?, ?, ?);", userid, channelid, message);
  },

  getMessages: async (channelid) => {
    return database.all("SELECT * FROM Channels WHERE ChannelID = ?", channelid);
  }
}
