// Setup basic express server
const express = require('express');
const app     = express();
const path    = require('path');
const server  = require('http').createServer(app);
const io      = require('socket.io')(server);
const port    = process.env.PORT || 3000;
const crypto  = require('crypto');
const db      = require('./db.js');

db.openDatabase();

process.on('SIGINT', () => {
  console.log("Bye");
  db.closeDatabase();
  process.exit();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }))

// Start server
server.listen(port, () => {
  console.log('Server listening at port %d', port);
  console.log('Dev link: http://localhost:3000');
});

// Routing for client-side files
app.use(express.static(path.join(__dirname, 'public'), {extensions:['html']}));

app.post('/register', (req, res) => {
  // TODO: broadcast room joins
  const username = req.body.username;
  const password = req.body.password;
  if(!username || !password) {
    res.status(400).json({"error": "Bad request"});
  } else {
    var salt = crypto.randomBytes(64);
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if(err) throw err;
      db.addUser(username, derivedKey.toString('hex'), salt.toString('hex'), req.body.iv, req.body.publicKey, req.body.privateKey)
      .then(() => { return res.json({})} )
      .catch((e) => { return res.json({"error": "Username taken"}) });
    });
  }
})

function db_room(room) {
  return {
    id: room.ChannelID,
    name: room.ChannelName,
    description: room.Description,
    private: room.Type == 'O',
    direct: room.Type == 'D',
    forceMembership: room.ForceJoin
  }
}

function db_user(user) {
  return { 
    id: user.UserID, 
    username: user.Username,
    active: isActive(user.UserID),
    publicKey: user.Pubkey,
  };
}

async function db_room_with_details(channel, userid, moveTo) {
  var db_channel = db_room(channel);
  var [participants, msgs] = await Promise.all([db.getParticipantsByChannel(channel.ChannelID),
                                                db.getChannelMessagesForUser(channel.ChannelID, userid)]);
  db_channel.members = participants.map((row) => row.UserID);
  db_channel.history = msgs.map((row) => {
    return {
      userid: row.UserID,
      message: row.Message,
      room: row.ChannelID,
      time: row.TimeSent,
    }
  });
  if(moveTo){
    db_channel.moveto = moveTo;
  }
  return db_channel;
}

async function getChannels(userid) {
  var channels = await db.getChannelsByUser(userid);
  var new_channels = channels.map((ch) => db_room_with_details(ch, userid));
  return await Promise.all(new_channels);
}

async function joinChannel(userid, socket, channelid) {
  var channel = await db.getChannel(channelid);
  if(channel && channel.Type == 'O') {
    await addParticipant(channelid, userid);
  }
}

async function leaveChannel(userid, socket, channelid) {
  var channel = await db.getChannel(channelid);
  if(channel && channel.Type != 'D' && !channel.ForceJoin) {
    await db.removeParticipant(channelid, userid);
    var participants = await db.getParticipantsByChannel(channelid);
    socket.leave('room' + channelid);
    sendToRoom(channelid, 'update_members', {
      room: channelid,
      members: participants.map((row) => row.UserID)
    });
    socket.emit('remove_room', {id: channelid});
  }
}

async function createChannel(name, description, type) {
  var chan = await db.addChannel(name, description, type, false);
  if(type == 'O') {
    io.emit('add_public_channel', {
      id: chan.lastID,
      name: name
    });
  }
  return chan;
}

async function addParticipant(channel, user) {
  var new_member = await db.addParticipant(channel, user);
  if(new_member) {
    if(isActive(user)){
      var chan = await db.getChannel(channel);
      socketmap[user].join('room' + channel);
      socketmap[user].emit('update_room', await db_room_with_details(chan, user, true));
    }
    var participants = await db.getParticipantsByChannel(channel);
    sendToRoom(channel, 'update_members', {
      room: channel,
      members: participants.map((row) => row.UserID)
    });
  }
}

async function addChannel(userid, socket, channelname, channeldesc, private) {
  var chan = await createChannel(channelname, channeldesc, private ? 'C' : 'O');
  if(chan) {
    await addParticipant(chan.lastID, userid);
  }
}

async function addUserToChannel(userid, socket, channelid, usertoadd) {
  var member = db.isParticipantInChannel(userid, channelid);
  if(member) {
    await addParticipant(channelid, usertoadd);
  }
}

async function requestDirectRoom(userid, socket, to) {
  var [to_user, dms] = await Promise.all([db.getUserById(to), db.getDirectChannel(userid, to)]);
  if(to_user){
    if(dms) {
      socket.emit('move_to_room', { id: dms.ChannelID });
    } else {
      var room = await createChannel(`Direct-${userid}-${to}`, "", "D");
      await Promise.all([addParticipant(room.lastID, userid), addParticipant(room.lastID, to)]);
    }
  }
}


///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

function sendToRoom(room, event, data) {
  io.to('room' + room).emit(event, data);
}

async function addMessageToRoom(userid, socket, roomid, msg) {
  var time = Date.now();
  var member = await db.isParticipantInChannel(userid, roomid);
  if(member) {
    var sent = await db.addMessage(userid, roomid, msg);
    if(sent){
      sendToRoom(roomid, 'new_message', {
        userid: userid,
        message: msg,
        room: roomid,
        time: time
      });
    }
  }
}

///////////////////////////
// IO connection handler //
///////////////////////////

const socketmap = {};

function isActive(userid) {
  return !!socketmap[userid];
}

io.on('connection', (socket) => {
  let loggedIn = false;
  let username = false;
  let userid;

  socket.on('new_message', (msg) => {
    if (loggedIn && msg.room && msg.message) {
      addMessageToRoom(userid, socket, msg.room, msg.message);
    }
  });

  socket.on('request_direct_room', req => {
    if (loggedIn && req.to) {
      requestDirectRoom(userid, socket, req.to);
    }
  });

  socket.on('add_channel', req => {
    if (loggedIn && req.name && req.private !== undefined) {
      addChannel(userid, socket, req.name, req.description, req.private);
    }
  });

  socket.on('join_channel', req => {
    if (loggedIn && req.id) {
      joinChannel(userid, socket, req.id);
    }
  });

  
  socket.on('add_user_to_channel', req => {
    if (loggedIn && req.channel && req.user) {
      addUserToChannel(userid, socket, req.channel, req.user);
    }
  });

  socket.on('leave_channel', req => {
    if (loggedIn && req.id) {
      leaveChannel(userid, socket, req.id);
    }
  });

  ///////////////
  // user join //
  ///////////////

  socket.on('join', (data) => {
    if (loggedIn || !data.username || !data.password) 
      return;

    username = data.username;
    db.getUserByName(username).then((dbUser) => {
      if(!dbUser) {
        return socket.emit('login', {
          error: "Invalid password"
        });
      }
      if(isActive(dbUser.UserID)) {
        return socket.emit('login', {
          error: "Already logged in"
        });
      }
      crypto.scrypt(data.password, Buffer.from(dbUser.Salt, 'hex'), 64, (err, derivedKey) => {
        if(err) throw err;
        if(derivedKey.toString('hex') != dbUser.Password) {
          socket.emit('login', {
            error: "Invalid password"
          });
        } else {
          loggedIn = true;
          userid = dbUser.UserID;
          socketmap[userid] = socket;
          Promise.all([
            getChannels(userid),
            db.getPublicChannels(),
            db.getUsers()
          ]).then(([rooms, publics, dbUsers]) => {
            let publicChannels = publics.map(db_room);
            let users = dbUsers.map(db_user);
            rooms.forEach((room) => socket.join('room' + room.id));
            socket.emit('login', {
              id: userid,
              users: users,
              rooms : rooms,
              publicChannels: publicChannels,
              publicKey: dbUser.Pubkey,
              privateKey: dbUser.Privkey,
              iv: dbUser.IV
            });
          });
          socket.broadcast.emit("user_state_change", db_user(dbUser));
        }
      });
    })
  });

  /////////////////
  // disconnects //
  /////////////////

  socket.on('disconnect', () => {
    if (loggedIn){
      delete socketmap[userid];
      loggedIn = false;
      db.getUserById(userid).then((user) => {
        socket.broadcast.emit("user_state_change", db_user(user));
      });
    }
  });
});
