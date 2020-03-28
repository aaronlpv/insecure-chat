const rooms = [];
let roomIdCounter = 0;

class Room {
    constructor(id, name, options) {
        this.id   =  id;
        this.name =  name;

        this.description = options.description || "";
      
        this.forceMembership = !!options.forceMembership;
        this.private         = !!options.private;
        this.direct          = !!options.direct;
  
        this.members = [];
        this.history = [];
    }

    getId() {
        return this.id;
    }

    getMembers() {
        return this.members;
    }

    getMemberCount(){
        return this.members.length;
    }

    addMember(user) {
        if (this.members.indexOf(user.name) === -1)
            this.members.push(user.name);
    }

    removeMember(user) {        
        const idx = this.members.indexOf(user.name);
        if (idx >= 0)
            this.members.splice(idx, 1);
    }

    getHistory() {
        return this.history;
    }

    addMessage(msg) {
        this.history.push(msg);
    }
}

module.exports = {
    addRoom: (name, options) => {
        const id = roomIdCounter++;
        const room = new Room(id, name, options);
        rooms[id] = room;
        return room;
    },

    getRooms: () => {
        return rooms;
    },

    getForcedRooms: () => {
        return rooms.filter(r => r.forceMembership);
    },

    getRoom: id => {
        return rooms[id];
    }
}