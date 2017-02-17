// Require jwt and moment software
var jwt = require('jwt-simple'),
    moment = require('moment');

// export the module
module.exports = {
  /*
  * Login Required Middleware
  */
  // function to check authentication
  ensureAuthenticated: function (req, res, next) {
    // Return a 401 if the user is not authorized
    if (!req.headers.authorization) {
      return res.status(401).send({ message: 'Please make sure your request has an Authorization header.' });
    }

    var token = req.headers.authorization.split(' ')[1];
    var payload = null;

    // Try to decode the token in the payload
    try {
      payload = jwt.decode(token, process.env.TOKEN_SECRET);
    }
    // return error if token cant be decoded
    catch (err) {
      return res.status(401).send({ message: err.message });
    }
    if (payload.exp <= moment().unix()) {
      return res.status(401).send({ message: 'Token has expired.' });
    }
    req.user = payload.sub;
    next();
  },

  /*
  * Generate JSON Web Token
  */
  createJWT: function (user) {
    var payload = {
      sub: user._id,
      iat: moment().unix(),
      exp: moment().add(14, 'days').unix()
    };
    return jwt.encode(payload, process.env.TOKEN_SECRET);
  }
};
