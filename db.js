var sqlite3 = require('sqlite3').verbose();
var sqlite = require('sqlite');

var database;

module.exports = {
  openDatabase: () => {
    return sqlite.open({
      filename: 'db.db',
      driver: sqlite3.Database
    }).then((db) => { database = db; db.configure("busyTimeout", 2000); });
  },

  closeDatabase: async () => {
    return database.close();
  },

  getUserByName: async (username) => {
    return database.get("SELECT * FROM Users WHERE Username = ?", username);
  },

  addUser: async (username, password, salt, iv, pubkey, privkey) => {
    return database.run("INSERT INTO Users(Username, Password, Salt, IV, Pubkey, Privkey)\
      VALUES (?, ?, ?, ?, ?, ?);", username, password, salt, iv, JSON.stringify(pubkey), privkey);
  }
}
