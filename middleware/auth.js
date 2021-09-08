const jwt = require('jsonwebtoken');
const config = require('config');

// Export middleware
module.exports = function(req, res, next) {
    // Get token from header
    const token = req.header('x-auth-token');

    // If no token, send 401
    if(!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // If there is token, but not valid send 401
    // If there is token, and it is valid, decode through jwtverify which gives access to req.user
    try {
        const decoded = jwt.verify(token, config.get('jwtSecret'));

        req.user = decoded.user;
        next();
    } catch(err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};