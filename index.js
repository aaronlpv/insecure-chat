// Setup basic express server
const express = require('express');
const app     = express();
const path    = require('path');
const server  = require('http').createServer(app);
const io      = require('socket.io')(server);
const port    = process.env.PORT || 3000;

const Users   = require('./users.js');
const Rooms   = require('./rooms.js');

// Load application config/state
require('./basicstate.js').setup(Users,Rooms);

// Start server
server.listen(port, () => {
  console.log('Server listening at port %d', port);
});

// Routing for client-side files
app.use(express.static(path.join(__dirname, 'public')));


///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

function sendToRoom(room, event, data) {
  io.to('room' + room.getId()).emit(event, data);
}

function newUser(name) {
  const user = Users.addUser(name);
  const rooms = Rooms.getForcedRooms();

  rooms.forEach(room => {
    addUserToRoom(user, room);
  });

  return user;
}

function newRoom(name, user, options) {
  const room = Rooms.addRoom(name, options);
  addUserToRoom(user, room);
  return room;
}

function newChannel(name, description, private, user) {
  return newRoom(name, user, {
    description: description,
    private: private
  });
}

function newDirectRoom(user_a, user_b) {
  const room = Rooms.addRoom(`Direct-${user_a.name}-${user_b.name}`, {
    direct: true,
    private: true,
  });

  addUserToRoom(user_a, room);
  addUserToRoom(user_b, room);

  return room;
}

function getDirectRoom(user_a, user_b) {
  const rooms = Rooms.getRooms().filter(r => r.direct 
    && (
      (r.members[0] == user_a.name && r.members[1] == user_b.name) ||
      (r.members[1] == user_a.name && r.members[0] == user_b.name)
    ));

  if (rooms.length == 1)
    return rooms[0];
  else
    return newDirectRoom(user_a, user_b);
}

function addUserToRoom(user, room) {
  user.addSubscription(room);
  room.addMember(user);

  sendToRoom(room, 'update_user', {
    room: room.getId(),
    username: user,
    action: 'added',
    members: room.getMembers()
  });
}

function removeUserFromRoom(user, room) {
  user.removeSubscription(room);
  room.removeMember(user);

  sendToRoom(room, 'update_user', {
    room: room.getId(),
    username: user,
    action: 'removed',
    members: room.getMembers()
  });
}

function addMessageToRoom(roomId, username, msg) {
  const room = Rooms.getRoom(roomId);

  msg.time = new Date().getTime();

  if (room) {
    sendToRoom(room, 'new message', {
      username: username,
      message: msg.message,
      room: msg.room,
      time: msg.time,
      direct: room.direct
    });

    room.addMessage(msg);
  }
}

function setUserActiveState(socket, username, state) {
  const user = Users.getUser(username);

  if (user)
    user.setActiveState(state);
  
  socket.broadcast.emit('user_state_change', {
    username: username,
    active: state
  });
}

///////////////////////////
// IO connection handler //
///////////////////////////

const socketmap = {};

io.on('connection', (socket) => {
  let loggedIn = false;
  let username = false;
  
  ///////////////////////
  // incomming message //
  ///////////////////////

  socket.on('new message', (msg) => {
    if (loggedIn) {
      console.log(msg);
      addMessageToRoom(msg.room, username, msg);
    }
  });

  /////////////////////////////
  // request for direct room //
  /////////////////////////////


  socket.on('request_direct_room', req => {
    if (loggedIn) {
      const a = Users.getUser(req.to);
      const b = Users.getUser(username);

      if(a && b) {
        const room = getDirectRoom(a, b);
        const roomCID = 'room' + room.getId();
        socket.join(roomCID);
        if (socketmap[a.name])
         socketmap[a.name].join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });

  socket.on('add_channel', req => {
    if (loggedIn) {
      const user = Users.getUser(username);
      console.log(req);
      const room = newChannel(req.name, req.description, req.private, user);
      const roomCID = 'room' + room.getId();
      socket.join(roomCID);

      socket.emit('update_room', {
        room: room,
        moveto: true
      });

      if (!room.private) {
        const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);
        socket.broadcast.emit('update_public_channels', {
          publicChannels: publicChannels
        });
      }
    }
  });

  socket.on('join_channel', req => {
    if (loggedIn) {
      const user = Users.getUser(username);
      const room = Rooms.getRoom(req.id)

      if(!room.direct && !room.private) {
        addUserToRoom(user, room);
        
        const roomCID = 'room' + room.getId();
        socket.join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });

  
  socket.on('add_user_to_channel', req => {
    if (loggedIn) {
      const user = Users.getUser(req.user);
      const room = Rooms.getRoom(req.channel)

      if(!room.direct) {
        addUserToRoom(user, room);
        
        const roomCID = 'room' + room.getId();
        socketmap[user.name].join(roomCID);

        socketmap[user.name].emit('update_room', {
          room: room,
          moveto: false
        });
      }
    }
  });

  socket.on('leave_channel', req => {
    if (loggedIn) {
      const user = Users.getUser(username);
      const room = Rooms.getRoom(req.id)

      if(!room.direct && !room.forceMembership) {
        removeUserFromRoom(user, room);
        
        const roomCID = 'room' + room.getId();
        socket.leave(roomCID);

        socket.emit('remove_room', {
          room: room.getId()
        });
      }
    }
  });

  ///////////////
  // user join //
  ///////////////

  socket.on('join', (p_username) => {
    if (loggedIn) 
      return;

    username = p_username;
    loggedIn = true;
    socketmap[username] = socket;

    const user = Users.getUser(username) || newUser(username);
    
    const rooms = user.getSubscriptions().map(s => {
      socket.join('room' + s);
      return Rooms.getRoom(s);
    });

    const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);

    socket.emit('login', {
      users: Users.getUsers().map(u => ({username: u.name, active: u.active})),
      rooms : rooms,
      publicChannels: publicChannels
    });

    setUserActiveState(socket, username, true);
  });

  /////////////////
  // disconnects //
  /////////////////

  socket.on('disconnect', () => {
    if (loggedIn)
      setUserActiveState(socket, username, false);
  });

  ////////////////
  // reconnects //
  ////////////////

  socket.on('reconnect', () => {
    if (loggedIn)
      setUserActiveState(socket, username, true);
  });

});
