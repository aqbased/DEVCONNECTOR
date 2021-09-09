const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
// Check and Validation Result can add 2nd parameter to route and check if request is an email or is a certain length for example
const { check, validationResult } = require("express-validator");
const bcrypt = require('bcryptjs');

const User = require('../../models/User');

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST api/auth
// @desc    Authenticate user and get token
// @access  Public
router.post(
    '/',
    [
        check('email', 'Please include a valid email')
            // Check for 'email', and set a custom error message
            // This makes sure the email field is an actual email
            .isEmail(),
        check('password', 'Password is required.')
            // Check for 'password', and set a custom error message
            // This makes sure the password being submitted isn't undefined
            .exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        // Set errors to validationResult which takes in the request
        // Check for errors
        if(!errors.isEmpty()) {
            // If there are errors, send a bad request error(400)
            return res.status(400).json({ errors: errors.array() });
        }
        // Destructure/pull name, email and password from req.body
        const { email, password } = req.body;

        try {
            let user = await User.findOne({ email })
            // If no user found with given credentials return error
            if(!user) {
                return res.status(400).json({ errors: [{ msg: 'Invalid Credentials' } ]});
            }
            
          // Bcrypt has a method called compare which takes plain text pass and encyrpted password and sees if they match
          const isMatch = await bcrypt.compare(password, user.password);

          if(!isMatch) {
              return res
                .status(400)
                .json({ errors: [{ msg: 'Invalid Credentials' }] });
          }

            // Return jsonwebtoken(When a user registers this logs them in right away)
            // Send user id as payload to identify user with token
            const payload = {
                user: {
                    id: user.id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                // Change expiresIn to 3600 before deploy
                { expiresIn: 360000 }, 
                (err, token) => {
                    if(err) throw err;
                    res.json({ token });
                });
        }   catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error');
            }
    }
);


module.exports = router;