const Promise = require('bluebird');
const emailVerification = require('../utils/send-email.js');
const jwt = require('../utils/jwt.js');
const { User } = require('../model/usermodel');

module.exports = function verifyChallenge(opts) {
  // TODO: add security logs
  // var remoteip = opts.remoteip;
  const { token, username } = opts;
  const { config } = this;
  const audience = opts.audience || config.defaultAudience;

  function verifyToken() {
    return emailVerification.verify.call(this, token, 'activate', config.validation.ttl > 0);
  }

  function hook(user) {
    return this.hook.call(this, 'users:activate', user, audience);
  }

  return Promise
    .bind(this, username)
    .then(username ? User.getUsername : verifyToken)
    .tap(User.activate)
    .tap(hook)
    .then(user => [user, audience])
    .spread(jwt.login);
};
