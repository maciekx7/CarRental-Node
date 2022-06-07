const jwt = require("jsonwebtoken");
const config = require("../config/auth.config.js");
const db = require("../models");
const roles = require("../config/models.config/user.roles.config");
const User = db.user;

verifyToken = (req, res, next) => {
  let token = req.headers["x-access-token"];

  if (!token) {
    return res.status(403).send({
      message: "Token not found!"
    });
  }

  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({
        message: "Unauthorized!"
      });
    }
    req.userId = decoded.id;
    next();
  });
};

verifyAdmin = (req, res, next) => {
console.log("Checking admin permision");
console.log(req.userId);
  User.findByPk(req.userId)
    .then(user => {
    console.log(user);
      if (!user) {
        return res.status(404).send({
          message: "User not found"
        });
      }

      if (user.role == roles.USER) {
        return res.status(403).send({
          message: "Require admin permissions!"
        });
      }

      if (user.role == roles.ADMIN) {
      console.log("ADMIN!");
        next();
      }
    })
    .catch(err => {
      res.status(500).send({
        message: err.message
      })
    });
};




const authJwt = {
  verifyToken: verifyToken,
  verifyAdmin: verifyAdmin
};



module.exports = authJwt;
