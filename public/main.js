'use strict';
function escape(str) {
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/\x00/g, '&#0;');
}

$(function() {
  // Initialize variables
  const $window = $(window);
  const $messages      = $('.messages'); // Messages area
  const $inputMessage  = $('#input-message'); // Input message input box
  const $usernameLabel = $('#user-name');
  const $userList      = $('#user-list');
  const $roomList      = $('#room-list');
  const $uta           = $('#usersToAdd');
  const $channelJoins  = $('#channelJoins');

  let connected = false;
  let username;
  let userid;
  let password;
  let derivedKey;
  let publicKey;
  let privateKey;
  let socket = io();

  let modalShowing = false;

  $('#addChannelModal').on('hidden.bs.modal', () => modalShowing = false)
                       .on('show.bs.modal',   () => modalShowing = true);
  $('#loginModal').on('hidden.bs.modal', () => modalShowing = false)
                  .on('show.bs.modal',   () => 
  {
    modalShowing = true;
    setTimeout(function (){
      $('#username').focus();
  }, 600);
  });

  $('#login-button').click(() => {
    var user = $('#username').val();
    var pass = $('#password').val();
    if(user == '') {
        return error('Username required');
    } else if(pass == '') {
        return error('Password required');
    }
    deriveSecrets(user, pass).then((res) => {
      username = user;
      password = res.password;
      derivedKey = res.key;
      socket.emit('join', {username: username, password: password});
    })
  })


  ///////////////
  // User List //
  ///////////////

  let users = {};

  function updateUsers(p_users) {
    p_users.forEach(u => users[u.id] = u);
    updateUserList();
  }

  function updateUser(user) {
    users[user.id] = user;
    updateUserList();
  }

  function updateUserList() {
    $uta.empty();

    $userList.empty();
    for (let [uid, user] of Object.entries(users)) {
      if (userid !== user.id) {
        $userList.append(`
          <li onclick="setDirectRoom(this)" data-direct="${user.id}" class="${user.active ? 'online' : 'offline'}">${escape(user.username)}</li>
        `);
        // append it also to the add user list
        $uta.append(`
          <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="addToChannel('${user.id}')">${escape(user.username)}</button>
        `); 
      }
    };
  }

  ///////////////
  // Room List //
  ///////////////

  let rooms = {};
  let channels = [];

  function updateRooms(p_rooms) {
    p_rooms.forEach((room) => rooms[room.id] = room);
    updateRoomList();
    updateChannelList();
  }

  function updateRoom(room) {
    rooms[room.id] = room;
    updateRoomList();
    updateChannelList();
  }

  function updateMembers(data) {
    rooms[data.room].members = data.members;
  }

  function removeRoom(id) {
    delete rooms[id];
    updateRoomList();
    updateChannelList();
  }

  function updateRoomList() {
    $roomList.empty();
    for (let [rid, r] of Object.entries(rooms)) {
      if (!r.direct)
        $roomList.append(`
          <li onclick="setRoom(${r.id})" data-room="${r.id}" class="${r.private ? "private" : "public"}">${escape(r.name)}</li>
        `);
    }
  }

function addPublicChannel(data) {
  channels.push(data);
  updateChannelList();
}

function updatePublicChannels(p_channels) {
  channels = p_channels;
  updateChannelList();
}

function updateChannelList() {
  $channelJoins.empty();
  channels.forEach((chan) => {
    if (!rooms[chan.id]) 
      $channelJoins.append(`
        <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="joinChannel(${chan.id})">${escape(chan.name)}</button>
      `);
  })
}

  //////////////
  // Chatting //
  //////////////

  let currentRoom = false;

  function setRoom(id) {
    const room = rooms[id];
    currentRoom = room;

    $messages.empty();
    room.history.forEach(m => addChatMessage(m));

    $userList.find('li').removeClass('active');
    $roomList.find('li').removeClass('active');

    if (room.direct) {
      const idx = room.members.indexOf(userid) == 0 ? 1 : 0;
      const user = room.members[idx];
      setDirectRoomHeader(user);

      $userList.find(`li[data-direct="${user}"]`)
        .addClass('active')
        .removeClass('unread')
        .attr('data-room', room.id);

    } else {
      $('#channel-name').text('#' + room.name);
      $('#channel-description').text(`👤 ${room.members.length} | ${room.description}`);
      $roomList.find(`li[data-room=${room.id}]`).addClass('active').removeClass('unread');
    }
    $('.roomAction').css('visibility', (room.direct || room.forceMembership) ? 'hidden' : 'visible');
  }
  window.setRoom = setRoom;

  function setDirectRoomHeader(user) {
    const username = users[user].username;
    $('#channel-name').text(username);
    $('#channel-description').text(`Direct message with ${username}`);
  }

  function setToDirectRoom(user) {
    setDirectRoomHeader(user);
    socket.emit('request_direct_room', { to: user });
  }

  window.setDirectRoom = (el) => {
    const user = el.getAttribute('data-direct');
    const room = el.getAttribute('data-room');

    if (room) {
      setRoom(parseInt(room));
    } else {
      setToDirectRoom(parseInt(user));
    }
  }

  function sendMessage() {
    let message = $inputMessage.val();

    if (message && connected && currentRoom !== false) {
      $inputMessage.val('');
      socket.emit('new_message', {message: message, room: currentRoom.id});
    }
  }


  function addChatMessage(msg) {
    let time = new Date(msg.time).toLocaleTimeString('en-US', { hour12: false, 
                                                        hour  : 'numeric', 
                                                        minute: 'numeric'});

    $messages.append(`
      <div class="message">
        <div class="message-avatar"></div>
        <div class="message-textual">
          <span class="message-user">${escape(users[msg.userid].username)}</span>
          <span class="message-time">${time}</span>
          <span class="message-content">${escape(msg.message)}</span>
        </div>
      </div>
    `);

    $messages[0].scrollTop = $messages[0].scrollHeight;
  }

  function messageNotify(msg) {
    $userList.find(`li[data-direct="${msg.userid}"]`).addClass('unread');
    $roomList.find(`li[data-room=${msg.room}]`).addClass('unread');
  }


  function addChannel() {
    const name = $('#inp-channel-name').val();
    const description = $('#inp-channel-description').val();
    const isPrivate = $('#inp-private').is(':checked');

    socket.emit('add_channel', {name: name, description: description, private: isPrivate});
  }
  window.addChannel = addChannel;


  function joinChannel(id) {
    socket.emit('join_channel', {id: id});
  }
  window.joinChannel = joinChannel;

  function addToChannel(user) {
    socket.emit('add_user_to_channel', {channel: currentRoom.id, user: user});   
  }
  window.addToChannel = addToChannel;

  function leaveChannel() {
    socket.emit('leave_channel', {id: currentRoom.id});   
  }
  window.leaveChannel = leaveChannel;

  /////////////////////
  // Keyboard events //
  /////////////////////

  $window.keydown(event => {
    if(modalShowing)
      return;
    
      // Auto-focus the current input when a key is typed
    if (!(event.ctrlKey || event.metaKey || event.altKey)) {
      $inputMessage.focus();
    }

    // When the client hits ENTER on their keyboard
    if (event.which === 13) {
        sendMessage();
    }

    // don't add newlines
    if (event.which === 13 || event.which === 10) {
      event.preventDefault();
    }
  });



  ///////////////////
  // server events //
  ///////////////////

  // Whenever the server emits 'login', log the login message
  socket.on('login', (data) => {
    console.log(data);
    if(data.error) {
      error(data.error);
      return;
    }
    connected = true;
    userid = data.id;
    $('#loginModal').modal('hide');
    $usernameLabel.text(username);

    decryptPrivateKey(derivedKey, data.privateKey, data.iv).then((key) => { privateKey = key; });

    updateUsers(data.users);
    updateRooms(data.rooms);
    updatePublicChannels(data.publicChannels);

    if(Object.keys(rooms).length > 0) {
      setRoom(Object.entries(rooms)[0][1].id);
    }
  });

  socket.on('update_public_channels', (data) => {
    updatePublicChannels(data.publicChannels);
  });

  // Whenever the server emits 'new message', update the chat body
  socket.on('new_message', (msg) => {
    const roomId = msg.room;
    const room = rooms[roomId];
    if (room) {
      room.history.push(msg);
    }

    if (roomId == currentRoom.id)
      addChatMessage(msg);
    else
      messageNotify(msg);
  });

  socket.on('update_user', data => {
    const room = rooms[data.room];
    if (room) {
      room.members = data.members;
      
      if (room === currentRoom)
        setRoom(data.room);
    }
  });

  socket.on('user_state_change', updateUser);
  
  socket.on('add_public_channel', addPublicChannel);

  socket.on('update_room', data => {
    console.log('ROOM');
    console.log(data);
    updateRoom(data);
    if (data.moveto)
      setRoom(data.id);
  });

  socket.on('update_members', data => {
    console.log('MEMBERS');
    console.log(data);
    updateMembers(data);
    if (data.room === currentRoom.id)
        setRoom(data.room);
  });

  socket.on('remove_room', data => {
    removeRoom(data.id);
    if(Object.keys(rooms).length > 0) {
      setRoom(Object.entries(rooms)[0][1].id);
    }
  });

  socket.on('move_to_room', data => setRoom(data.id));

  $('#loginModal').modal('show');
});
