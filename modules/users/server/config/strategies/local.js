'use strict';

/**
 * Module dependencies
 */
var passport = require('passport'),
  LocalStrategy = require('passport-local').Strategy,
  User = require('mongoose').model('User'),
  Passport = require('mongoose').model('Passport');

module.exports = function () {
  // Use local strategy
  passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },
  function (usernameOrEmail, password, done) {
    User.findOne({
      email: usernameOrEmail.toLowerCase()
    }, function (err, user) {
      if (err) {
        return done(err);
      }

      Passport.findOne({
        provider: 'local',
        userId: user
      }, function(err, pass) {
        if (err) {
          return done(err);
        }

        if (!pass || !pass.authenticate(password)) {
          return done(null, false, {
            message: 'Invalid username or password (' + (new Date()).toLocaleTimeString() + ')'
          });
        }

        return done(null, user);
      });
    });
  }));
};
