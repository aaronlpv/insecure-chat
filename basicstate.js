module.exports = {
    setup: (Users, Rooms) => {

        Rooms.addRoom("general", {forceMembership: true, description: "boring stuff"});
        Rooms.addRoom("random" , {forceMembership: true, description: "random!"});
        Rooms.addRoom("private" ,{forceMembership: true, description: "some private channel", private: true});
    }
}