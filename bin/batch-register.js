#!/usr/bin/env node

// quickly registers users from CLI
/* eslint-disable no-console */

const is = require('is');
const Promise = require('bluebird');
const conf = require('ms-conf');
const assert = require('assert');
const AMQPTransport = require('ms-amqp-transport');
const getStdin = require('get-stdin');
const merge = require('lodash/merge');
const defaults = require('lodash/defaults');
const gen = require('password-generator');
const defaultOpts = require('../lib/config');
const { CHALLENGE_TYPE_EMAIL } = require('../lib/constants');

const config = merge({}, defaultOpts, conf.get('/'));
const amqpConfig = config.amqp.transport;
const audience = config.jwt.defaultAudience;
const prefix = config.router.routes.prefix;

/**
 * Registers batch users from stdin
 */
function registerUsers(users) {
  return AMQPTransport
    .connect(amqpConfig)
    .then(amqp => (
      Promise
        .map(users, user => (
          amqp.publishAndWait(`${prefix}.register`, user, { timeout: 5000 })
        ))
        .finally(() => amqp.close())
    ))
    .return(users);
}

// ensure we do not bind to queues
delete amqpConfig.queue;
delete amqpConfig.neck;
delete amqpConfig.listen;

// read data from stdin
return getStdin()
  .then(input => JSON.parse(input))
  .then((info) => {
    assert.equal(typeof info.common, 'object');
    assert.ok(Array.isArray(info.users));
    assert.ok(info.users.length > 0);

    return info.users.map((user) => {
      const data = is.string(user)
        ? user.split(/\s/g)
        : user;

      const [firstName, lastName, username] = data;

      assert.ok(firstName);
      assert.ok(lastName);
      assert.ok(username);

      return {
        audience,
        username,
        password: gen(6),
        metadata: defaults({ firstName, lastName }, info.common),
        activate: true,
        challengeType: CHALLENGE_TYPE_EMAIL,
        skipPassword: false,
      };
    });
  })
  .then(registerUsers)
  .then(users => (
    users.forEach(user => (
      console.info('[%s] - %s', user.username, user.password)
    ))
  ))
  .then(() => {
    return process.exit();
  })
  .catch((err) => {
    console.info(err);
    setImmediate(() => { throw err; });
  });
