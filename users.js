const users = {};

class User {
    constructor(name) {
        this.name = name;

        this.active = false;
        this.subscriptions = [];
    }

    getSubscriptions() {
        return this.subscriptions;
    }

    addSubscription(room) {
        const id = room.getId();

        if (this.subscriptions.indexOf(id) === -1)
            this.subscriptions.push(id);
    }

    removeSubscription(room) {
        const id = room.getId();

        const idx = this.subscriptions.indexOf(id);
        if (idx >= 0)
            this.subscriptions.splice(idx, 1);
    }

    setActiveState(b) {
        this.active = b;
    }

}

module.exports = {
    addUser: name => {
        const user = new User(name);
        users[name] = user;
        return user;
    },

    getUser: name => {
        return users[name];
    },

    getUsers: () => {
        return Object.values(users);
    }
}