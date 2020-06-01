'use strict';
function escape(str) {
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/\x00/g, '&#0;');
}

async function generateSymmetricKey() {
  return JSON.stringify(
    await crypto.subtle.exportKey(
      "jwk",
      await crypto.subtle.generateKey(
        {name: "AES-CBC", length: 256},
        true,
        ["encrypt", "decrypt"])));
}

$(function() {
  // Initialize variables
  const $window        = $(window);
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
  let derivedKey;
  let encKey;
  let hmacKey;
  let signKey;
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

  function doLogin() {
    var user = $('#username').val();
    var pass = $('#password').val();
    if(user == '') {
        return error('Username required');
    } else if(pass == '') {
        return error('Password required');
    }
    deriveSecrets(user, pass).then((res) => {
      username = user;
      encKey = res.encKey;
      hmacKey = res.hmacKey;
      socket.emit('join', {username: username, password: res.authKey});
    })
  }

  $('#login-button').click(doLogin);
  $('#password').keydown(e => { if(e.which == 13) doLogin() });


  ///////////////
  // User List //
  ///////////////

  let users = {};

  async function userImportKey(user) {
    console.log("about to import");
    console.log(user.publicKey);
    user.publicKey = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(user.publicKey),
      {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      false,
      ["encrypt"]
    );
  }

  function updateUsers(p_users) {
    p_users.forEach(u => { users[u.id] = u; userImportKey(u); } );
    updateUserList();
  }

  function updateUser(user) {
    users[user.id] = user;
    userImportKey(user);
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
    p_rooms.forEach((room) => { rooms[room.id] = room; room.keys = {} });
    updateRoomList();
    updateChannelList();
  }

  function updateRoom(room) {
    rooms[room.id] = room;
    room.keys = {};
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

  async function sendMessage() {
    let message = $inputMessage.val();

    if (message && connected && currentRoom !== false) {
      $inputMessage.val('');
      const encryptedMessage = bufferToHex(await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: new Uint8Array(16).fill(1) }, // FIXME
        currentRoom.keys[currentRoom.lastKey],
        new TextEncoder().encode(message)
      ));
      socket.emit('new_message', 
        { message: encryptedMessage, room: currentRoom.id, key: currentRoom.lastKey });
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
  socket.on('login', async data => {
    console.log(data);
    if(data.error) {
      error(data.error);
      return;
    }
    connected = true;
    userid = data.id;
    $('#loginModal').modal('hide');
    $usernameLabel.text(username);

    const privateKeyPromise = decryptPrivateKeys(encKey, hmacKey, data.privateKeys, data.iv, data.mac);

    updateUsers(data.users);
    updateRooms(data.rooms);
    updatePublicChannels(data.publicChannels);

    const privateKeys = await privateKeyPromise;
    privateKey = privateKeys.privateKey;
    signKey = privateKeys.signKey;
    console.log("KEYS");
    console.log(privateKeys);
    await Promise.all(data.rooms.map(async room => {
      await roomDecryptMessages(room);
      if(room.leader == userid) {
        rekeyRoom(room.id);
      }
    }));

    if(Object.keys(rooms).length > 0) {
      setRoom(Object.entries(rooms)[0][1].id);
    }
  });

  async function importRoomKey(room, keyid, key) {
    rooms[room].keys[keyid] = 
      await crypto.subtle.importKey(
        'jwk',
        JSON.parse(new TextDecoder().decode(
          await crypto.subtle.decrypt(
            {
              name: "RSA-OAEP",
              modulusLength: 4096,
              publicExponent: new Uint8Array([1, 0, 1]),
              hash: "SHA-256"
            },
            privateKey,
            hexToBuffer(key)))),
          { name: 'AES-CBC', length: 256 },
        false,
        ['encrypt', 'decrypt']);
    rooms[room].lastKey = keyid;
  }

  async function receiveMessage(msg, history) {
    const roomId = msg.room;
    const room = rooms[roomId];

    if(msg.key) {
      const key = room.keys[msg.key];
      const message = new TextDecoder().decode(
        await crypto.subtle.decrypt(
          { name: 'AES-CBC', iv: new Uint8Array(16).fill(1) }, // FIXME
          key,
          hexToBuffer(msg.message)
        )
      );
      const actual_msg = { time: msg.time, userid: msg.userid, message: message, room: roomId };
      (history || room.history).push(actual_msg);

      if(!history) {
        if (roomId == currentRoom.id)
          addChatMessage(actual_msg);
        else
          messageNotify(actual_msg);
      }
    } else {
      const message = JSON.parse(msg.message);
      if(message.keys[userid]){
        await importRoomKey(room.id, message.keyid, message.keys[userid]);
      }
      
    }
  }

  // Whenever the server emits 'new message', update the chat body
  socket.on('new_message', async msg => {
    console.log(msg);
    receiveMessage(msg);
  });

  socket.on('user_state_change', updateUser);
  
  socket.on('add_public_channel', addPublicChannel);

  socket.on('update_room', async data => {
    console.log('ROOM');
    console.log(data);
    updateRoom(data);
    await roomDecryptMessages(data);
    if(data.leader == userid) {
      rekeyRoom(data.id);
    }
    if (data.moveto)
      setRoom(data.id);
  });

  async function rekeyRoom(room) {
    const key = await generateSymmetricKey();
    const keys = {};
    for(let member of rooms[room].members) {
      keys[member] = bufferToHex(
        await crypto.subtle.encrypt(
          {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
          },
          users[member].publicKey,
          new TextEncoder('utf-8').encode(key)));
    }
    socket.emit('new_message', 
      { message: JSON.stringify({ keyid: Math.floor(Math.random() * 100000), keys: keys }), 
        room: room });
  }

  async function roomDecryptMessages(room) {
    let history = [];
    for(let msg of room.history){
      await receiveMessage(msg, history);
    }
    room.history = history;
  }

  socket.on('update_members', data => {
    console.log('MEMBERS');
    console.log(data);
    updateMembers(data);
    if(data.leader == userid)
      rekeyRoom(data.room);
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
