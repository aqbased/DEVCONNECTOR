const express = require('express');
const router = express.Router();
// Gravatar links an image from an email
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
// Check and Validation Result can add 2nd parameter to route and check if request is an email or is a certain length for example
const { check, validationResult } = require("express-validator");

// Bring in User model
const User = require('../../models/User')

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
    '/',
    [
        check('name', 'Name is required')
            // Check for 'name', and set a custom error message
            // This makes sure the name field isn't empty
            .not()
            .isEmpty(),
        check('email', 'Please include a valid email')
            // Check for 'email', and set a custom error message
            // This makes sure the email field is an actual email
            .isEmail(),
        check('password', 'Please enter a password with 6 or more characters')
            // Check for 'password', and set a custom error message
            // This makes sure the password is at least 6 characters long
            .isLength({ min: 6 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        // Set errors to validationResult which takes in the request
        // Check for errors
        if(!errors.isEmpty()) {
            // If there are errors, send a bad request error(400)
            return res.status(400).json({ errors: errors.array() });
        }
        // Destructure and pull name, email and password from req.body
        const { name, email, password } = req.body;

        try {
            let user = await User.findOne({ email })
            // See if user exists
            if(user) {
                res.status(400).json({ errors: [ { msg: 'User already exists' } ]});
            }
            // Get users gravatar(based on email)
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            })

            user = new User({
                name,
                email,
                avatar,
                password
            });

            // Encrypt password(bcrypt)
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            // Save user in db
            await user.save();
    
            // Return jsonwebtoken(When a user registers this logs them in right away)
            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 360000 }, 
                (err, token) => {
                    if(err) throw err;
                    res.json({ token });
                });
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error');
        }
    }
);

module.exports = router;