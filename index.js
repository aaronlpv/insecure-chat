'use strict';
// Setup basic express server
const express              = require('express');
const app                  = express();
const nunjucks             = require('nunjucks');
const helmet               = require('helmet');
const cookieParser         = require('cookie-parser');
const csurf                = require('csurf')
const path                 = require('path');
const server               = require('http').createServer(app);
const io                   = require('socket.io')(server);
const {RateLimiterMemory}  = require('rate-limiter-flexible');
const port                 = process.env.PORT || 3000;
const crypto               = require('crypto');
const db                   = require('./db.js');

// 1 login attempt per IP per second
const rateLimiter = new RateLimiterMemory({ points: 1, duration: 1 });

db.openDatabase();

process.on('SIGINT', () => {
  console.log('Bye');
  db.closeDatabase();
  process.exit();
});

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(csurf({ cookie: true }));

// Start server
server.listen(port, () => {
  console.log('Server listening at port %d', port);
  console.log('Dev link: http://localhost:3000');
});

// Routing for client-side files
app.use(express.static(path.join(__dirname, 'public'), {extensions:['html']}));
app.set('views', path.join(__dirname, 'views'));

// Nunjucks template setup (for CSRF)
nunjucks.configure('views', {
  express: app,
  autoescape: true
});
app.set('view engine', 'html');

app.get('/register', (req, res) => {
  res.render('register.html', {csrfToken: req.csrfToken()});
});

app.post('/register', async (req, res) => {
  console.log(req.body);
  const username = req.body.username;
  const password = req.body.password;
  const iv       = req.body.iv;
  const hmac     = req.body.hmac;
  const privateKeys = req.body.privateKeys;
  const rsaPublicKey = req.body.rsaPublicKey;
  const ecdsaPublicKey = req.body.ecdsaPublicKey;
  if(!username || !password || !iv || !hmac || !privateKeys || !rsaPublicKey || !ecdsaPublicKey) {
    res.status(400).json({error: 'Bad request'});
  } else {
    const salt = crypto.randomBytes(64);
    crypto.scrypt(password, salt, 64, async (err, derivedKey) => {
      if(err) throw err;
      try {
        var user = await db.addUser(username, derivedKey.toString('hex'), salt.toString('hex'),
          privateKeys, iv, hmac, ecdsaPublicKey, rsaPublicKey);
      } catch {
        return res.json({error: 'Username taken'})
      }
      const new_user = await db.getUserById(user.lastID);
      io.emit('user_state_change', db_user(new_user));
      await Promise.all((await db.getForceChannels()).map(c => addParticipant(c.ChannelID, user.lastID)));
      res.json({});
    });
  }
})

function db_room(room) {
  return {
    id: room.ChannelID,
    name: room.ChannelName,
    description: room.Description,
    private: room.Type == 'C',
    direct: room.Type == 'D',
    forceMembership: room.ForceJoin
  }
}

function db_user(user) {
  return { 
    id: user.UserID, 
    username: user.Username,
    active: isActive(user.UserID),
    publicKey: user.PubKey,
    signKey: user.SignKey
  };
}

async function db_room_with_details(channel, userid, moveTo) {
  const db_channel = db_room(channel);
  const [participants, msgs] = await Promise.all([db.getParticipantsByChannel(channel.ChannelID),
                                                  db.getChannelMessagesForUser(channel.ChannelID, userid)]);
  const participantIds = participants.map((row) => row.UserID);
  db_channel.members = participantIds;
  db_channel.leader = participantIds.find(p => isActive(p));
  db_channel.history = msgs.map((row) => {
    return {
      userid: row.UserID,
      message: row.Message,
      room: row.ChannelID,
      time: row.TimeReceived,
      key: row.Key
    }
  });
  if(moveTo){
    db_channel.moveto = moveTo;
  }
  return db_channel;
}

async function getChannelsForUser(userid) {
  return await Promise.all((await db.getChannelsByUser(userid)).map((ch) => db_room_with_details(ch, userid)));
}

async function createChannel(name, description, type) {
  const chan = await db.addChannel(name, description, type, false);
  if(type == 'O') {
    io.emit('add_public_channel', {
      id: chan.lastID,
      name: name
    });
  }
  return chan;
}

async function addParticipant(channel, user) {
  try {
    await db.addParticipant(channel, user);
  } catch { return; }
  if(isActive(user)){
    const chan = await db.getChannel(channel);
    socketmap[user].join('room' + channel);
    socketmap[user].emit('update_room', await db_room_with_details(chan, user, true));
  }
  await updateMembers(channel);
}

async function updateMembers(channel) {
  const participants = (await db.getParticipantsByChannel(channel)).map((row) => row.UserID);
  sendToRoom(channel, 'update_members', {
    room: channel,
    members: participants,
    leader: participants.find(p => isActive(p))
  });
}

///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

function sendToRoom(room, event, data) {
  io.to('room' + room).emit(event, data);
}

///////////////////////////
// IO connection handler //
///////////////////////////

const socketmap = {};

function isActive(userid) {
  return !!socketmap[userid];
}

io.on('connection', (socket) => {
  let ip = socket.request.connection.remoteAddress;
  let loggedIn = false;
  let username;
  let userid;

  socket.on('new_message', async msg => {
    console.log(msg);
    if (loggedIn && msg.room && msg.message) {
      const time = Date.now();
      const member = await db.isParticipantInChannel(userid, msg.room);
      if(member) {
        const sent = await db.addMessage(userid, msg.room, msg.message, msg.key);
        if(sent){
          sendToRoom(msg.room, 'new_message', {
            userid: userid,
            message: msg.message,
            room: msg.room,
            time: time,
            key: msg.key
          });
        }
      }
    }
  });

  socket.on('request_direct_room', async req => {
    if (loggedIn && req.to) {
      const [to_user, dms] = await Promise.all([db.getUserById(req.to), db.getDirectChannel(userid, req.to)]);
      if(to_user){
        if(dms) {
          socket.emit('move_to_room', { id: dms.ChannelID });
        } else {
          const room = await createChannel(`Direct-${userid}-${req.to}`, '', 'D');
          await db.addParticipant(room.lastID, userid);
          await db.addParticipant(room.lastID, req.to);
          socket.join('room' + room.lastID);
          socketmap[req.to].join('room' + room.lastID);
          const chan = await db_room_with_details(await db.getChannel(room.lastID), userid, true);
          socket.emit('update_room', chan);
          socketmap[req.to].emit('update_room', chan);
        }
      }
    }
  });

  socket.on('add_channel', async req => {
    if (loggedIn && req.name && req.private !== undefined) {
      const room = await createChannel(req.name, req.description, req.private ? 'C' : 'O');
      await db.addParticipant(room.lastID, userid);
      socket.join('room' + room.lastID);
      socket.emit('update_room', await db_room_with_details(await db.getChannel(room.lastID), userid, true));
    }
  });

  socket.on('join_channel', async req => {
    if (loggedIn && req.id) {
      const channel = await db.getChannel(req.id);
      if(channel && channel.Type == 'O') {
        await addParticipant(req.id, userid);
      }
    }
  });

  
  socket.on('add_user_to_channel', async req => {
    if (loggedIn && req.channel && req.user) {
      if(db.isParticipantInChannel(userid, req.channel)) {
        await addParticipant(req.channel, req.user);
      }
    }
  });

  socket.on('leave_channel', async req => {
    if (loggedIn && req.id) {
      const channel = await db.getChannel(req.id);
      if(channel && channel.Type != 'D' && !channel.ForceJoin &&
          (await db.removeParticipant(req.id, userid)).changes > 0) {
        socket.leave('room' + req.id);
        await updateMembers(req.id);
        socket.emit('remove_room', {id: req.id});
      }
    }
  });

  ///////////////
  // user join //
  ///////////////

  socket.on('join', async data => {
    console.log(data);
    const error = msg => socket.emit('login', {error: msg});
    if (loggedIn || !data.username || !data.password) 
      return;

    try {
      await rateLimiter.consume(ip);
    } catch {
      return error('Slow down');
    }

    username = data.username;
    const dbUser = await db.getUserByName(username);
    if(!dbUser) {
      return error('Invalid password');
    }
    if(isActive(dbUser.UserID)) {
      return error('Already logged in');
    }
    crypto.scrypt(data.password, Buffer.from(dbUser.Salt, 'hex'), 64, (err, derivedKey) => {
      if(err) throw err;
      if(derivedKey.toString('hex') != dbUser.Password) {
        return error('Invalid password');
      } else {
        loggedIn = true;
        userid = dbUser.UserID;
        socketmap[userid] = socket;
        Promise.all([
          getChannelsForUser(userid),
          db.getPublicChannels(),
          db.getUsers()
        ]).then(([rooms, publics, dbUsers]) => {
          const publicChannels = publics.map(db_room);
          const users = dbUsers.map(db_user);
          rooms.forEach((room) => socket.join('room' + room.id));
          socket.emit('login', {
            id: userid,
            users: users,
            rooms : rooms,
            publicChannels: publicChannels,
            privateKeys: dbUser.PrivateKeys,
            iv: dbUser.IV,
            mac: dbUser.MAC
          });
        });
        socket.broadcast.emit('user_state_change', db_user(dbUser));
      }
    });
  });

  /////////////////
  // disconnects //
  /////////////////

  socket.on('disconnect', () => {
    if (loggedIn){
      delete socketmap[userid];
      loggedIn = false;
      db.getUserById(userid).then((user) => {
        socket.broadcast.emit('user_state_change', db_user(user));
      });
    }
  });
});
