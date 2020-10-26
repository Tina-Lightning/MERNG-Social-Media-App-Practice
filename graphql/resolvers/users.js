const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { SECRET_KEY } = require("../../config");
const User = require("../../models/User");

module.exports = {
    Mutation: {
        async register(_,
            {
                registerInput: { username, email, password, confirmPassword }
            },
            context,
            info
        ) {
            // Validate User Data
            // Make sure user doesn't already exist
            // Hash the password and create an auth token
            password = await bcrypt.hash(password, 12);

            const newUSer = new User({
                email,
                username,
                password,
                createdAt: new Date().toDateString()
            });

            const res = await newUSer.save();

            const token = jwt.sign({
                id: res.id,
                email: res.email,
                username: res.username
            }, SECRET_KEY, { expiresIn: "1h" });

            return {
                ...res._doc,
                id: res._id,
                token
            };
        }
    }
};

