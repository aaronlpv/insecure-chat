'use strict';

// html escape, based off code from StackOverflow and Google Guava
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
      'jwk',
      await crypto.subtle.generateKey(
        {name: 'AES-CBC', length: 256},
        true,
        ['encrypt', 'decrypt'])));
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
  let encKey;
  let hmacKey;
  let signKey;
  let privateKey;
  let socket = io();

  let modalShowing = false;

  $('#addChannelModal').on('hidden.bs.modal', () => modalShowing = false)
                       .on('show.bs.modal',   () => modalShowing = true);
  $('#identityModal').on('hidden.bs.modal', () => modalShowing = false)
                       .on('show.bs.modal',   () => modalShowing = true);
  $('#loginModal').on('hidden.bs.modal', () => modalShowing = false)
                  .on('show.bs.modal',   () => {
    modalShowing = true;
    setTimeout(function (){
      $('#username').focus();
    }, 600);
  });

  $('#login-button').click(doLogin);

  $('#identitycheck').click(async () => {
    const room = currentRoom;
    if(currentRoom.direct) {
      const identity = $('#otheridentity').val();
      const user = users[room.members[room.members.indexOf(userid) == 0 ? 1 : 0]];
      var valid = await verify(hexToBuffer(identity), `${user.username}#${user.id}`, user.signKey);
      $('#identity-output').text(valid ? 'OK' : 'BAD');
    }
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

  ////////////////
  // Encryption //
  ////////////////

  // import a user's public key and signing key
  async function userImportKey(user) {
    const userPubKeyPromise = crypto.subtle.importKey(
      'jwk',
      JSON.parse(user.publicKey),
      AsymmetricAlgo,
      false,
      ['encrypt']
    );
    const userSignKeyPromise = crypto.subtle.importKey(
      'jwk',
      JSON.parse(user.signKey),
      SignAlgo,
      false,
      ['verify']
    );
    const userPubKey = await userPubKeyPromise;
    const userSignKey = await userSignKeyPromise;
    if(await verify(hexToBuffer(user.ident), user.publicKey, userSignKey)) {
      user.publicKey = userPubKey;
      user.signKey = userSignKey;
    } else {
      throw new Error('User keys invalid');
    }
  }

  // import a symmetric room key
  async function importRoomKey(room, keyid, key) {
    rooms[room].keys[keyid] = 
      await crypto.subtle.importKey(
        'jwk',
        JSON.parse(new TextDecoder().decode(
          await crypto.subtle.decrypt(
            AsymmetricAlgo,
            privateKey,
            hexToBuffer(key)))),
          { name: 'AES-CBC', length: 256 },
        false,
        ['encrypt', 'decrypt']);
    rooms[room].lastKey = keyid;
  }

  // message to signature material
  async function messageMacMaterial(msg, send) {
    return `${msg.message}|${send ? userid : msg.userid}|${msg.room}|${send ? msg.time : msg.timeSent}|${msg.iv}|${msg.key}`;
  }
  
  // add a MAC to a message
  async function messageAddMac(msg){
    const mac = bufferToHex(await sign(messageMacMaterial(msg, true), signKey));
    msg.mac = mac;
    return msg;
  }

  async function rekeyRoom(room) {
    const key = await generateSymmetricKey();
    const keys = {};
    for(let member of rooms[room].members) {
      keys[member] = bufferToHex(
        await crypto.subtle.encrypt(
          AsymmetricAlgo,
          users[member].publicKey,
          new TextEncoder('utf-8').encode(key)));
    }
    socket.emit('new_message', 
      await messageAddMac({ message: JSON.stringify({ keyid: Math.floor(Math.random() * 100000), keys: keys }), 
        room: room,
        time: Date.now() }));
  }

  // decrypt message from a room's history
  async function roomDecryptMessages(room) {
    let history = [];
    for(let msg of room.history) {
      try {
        await receiveMessage(msg, history);
      } catch {
        console.log('Could not decrypt a message from history');
      }

    }
    room.history = history;
  }

  // receive a single message or rekey
  async function receiveMessage(msg, history) {
    const roomId = msg.room;
    const room = rooms[roomId];
    let msgToAdd;

    const valid = await verify(hexToBuffer(msg.mac), messageMacMaterial(msg, false), users[msg.userid].signKey);
    if(!valid // signature check failed
       || Math.abs(msg.timeSent - msg.time) > 5000 // more than 5 seconds between server receive time and message send time
       || (room.lastTime && room.lastTime > msg.time) // message sent out of order
       || !history && !room.members.includes(msg.userid)) // message from user not currently in the channel
      return;

    if(msg.key) { // regular message
      const key = room.keys[msg.key];
      if(key){
        const message = new TextDecoder().decode(
          await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: hexToBuffer(msg.iv) },
            key,
            hexToBuffer(msg.message)
          )
        );
        msgToAdd = { room: msg.room, time: msg.time, userid: msg.userid, message: message };
      }
    } else { // rekey
      const message = JSON.parse(msg.message);
      if(message.keys[userid]){
        await importRoomKey(room.id, message.keyid, message.keys[userid]);
      }
      msgToAdd = { room: msg.room, time: msg.time, userid: msg.userid, rekey: true };
    }
    room.lastTime = msg.time;

    if(msgToAdd) {
      (history || room.history).push(msgToAdd);
      if(!history) {
        if (roomId == currentRoom.id) {
          addChatMessage(msgToAdd);
        } else if(!msgToAdd.rekey) {
          messageNotify(msgToAdd);
        }
      }
    }
  }

  ///////////////
  // User List //
  ///////////////

  let users = {};

  async function updateUsers(p_users) {
    await Promise.all(p_users.map(u => updateUser(u, false)));
    updateUserList();
  }

  async function updateUser(user, update) {
    if(users[user.id])
      return;
    try {
      await userImportKey(user);
      users[user.id] = user;
      if(update) {
        updateUserList();
      }
    } catch {
      console.log(`Could not import user keys for user "${user.username}"`);
    }
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
    if(rooms[room.id])
      return;
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
      $('#otheridentity-header').text(`${users[user].username}'s Identity`);

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
    $('.identityAction').css('visibility', room.direct ? 'visible' : 'hidden');
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
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const encryptedMessage = bufferToHex(await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: iv },
        currentRoom.keys[currentRoom.lastKey],
        new TextEncoder().encode(message)
      ));
      const ivHex = bufferToHex(iv);
      const time = Date.now();
      const messageToSend = { message: encryptedMessage, room: currentRoom.id, key: currentRoom.lastKey, iv: ivHex, time: time };

      socket.emit('new_message', await messageAddMac(messageToSend));
    }
  }

  function addChatMessage(msg) {
    let time = new Date(msg.time).toLocaleTimeString('en-US', { hour12: false, 
                                                        hour  : 'numeric', 
                                                        minute: 'numeric'});
    if(msg.rekey) {
      $messages.append(`
      <div class="rekey">
      ${time} <span class="message-user">&nbsp;${escape(users[msg.userid].username)}</span>#${msg.userid} issued a rekey
      </div>
    `);
    } else {
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
    }
    $messages[0].scrollTop = $messages[0].scrollHeight;
  }

  function messageNotify(msg) {
    if(rooms[msg.room].direct){
      $userList.find(`li[data-direct="${msg.userid}"]`).addClass('unread');
    } else {
      $roomList.find(`li[data-room=${msg.room}]`).addClass('unread');
    }
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

  $('#password').keydown(e => { if(e.which == 13) doLogin() });

  ///////////////////
  // server events //
  ///////////////////

  // User login
  socket.on('login', async data => {
    if(data.error) {
      error(data.error);
      return;
    }
    connected = true;
    userid = data.id;
    $('#loginModal').modal('hide');
    $usernameLabel.text(username);

    const privateKeyPromise = decryptPrivateKeys(encKey, hmacKey, data.privateKeys, data.iv, data.mac);

    const userUpdate = updateUsers(data.users);
    updateRooms(data.rooms);
    updatePublicChannels(data.publicChannels);

    await userUpdate;
    const privateKeys = await privateKeyPromise;
    if(!privateKeys) {
      // we could not import our encrypted private keys -> abort
      throw new Error('Server is misbehaving');
    }
    privateKey = privateKeys.privateKey;
    signKey = privateKeys.signKey;
    $('#myidentity').val(bufferToHex(await sign(`${username}#${userid}`, signKey)));
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

  // New chat message or rekey
  socket.on('new_message', async msg => {
    try {
      receiveMessage(msg);
    } catch {
      console.log('Could not receive new message');
    }
  });

  // Newly registered user
  socket.on('update_user', data => {
    if(connected)
      updateUser(data, true);
  });

  // User went offline or online
  socket.on('user_state_change', data => {
    if(connected){
      users[data.id].active = data.active;
      updateUserList();
    }
  });
  
  // New public channel we could join
  socket.on('add_public_channel', data =>{
    if(connected)
      addPublicChannel(data);
  });

  // New room we are a member of
  socket.on('update_room', async data => {
    updateRoom(data);
    await roomDecryptMessages(data);
    if(data.leader == userid) {
      rekeyRoom(data.id);
    }
    if (data.moveto)
      setRoom(data.id);
  });

  // User left or joined a room we are member of
  socket.on('update_members', data => {
    updateMembers(data);
    if(data.leader == userid)
      rekeyRoom(data.room);
    if (data.room === currentRoom.id)
      setRoom(data.room);
  });

  // We should remove a room from our list
  socket.on('remove_room', data => {
    removeRoom(data.id);
    if(Object.keys(rooms).length > 0) {
      setRoom(Object.entries(rooms)[0][1].id);
    }
  });

  // We should focus a room
  socket.on('move_to_room', data => setRoom(data.id));


  // open the login dialog
  $('#loginModal').modal('show');
});
