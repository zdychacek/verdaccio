var crypto = require('crypto')
var crypt3 = require('./crypt3')
var locker = require('../../file-locking')

// this function neither unlocks file nor closes it
// it'll have to be done manually later
function lock_and_read(name, cb) {
  locker.readFile(name, {lock: true}, function (err, res) {
    if (err) {
      return cb(err)
    }
    return cb(null, res)
  })
}

// close and unlock file
function unlock_file(name, cb) {
  locker.unlockFile(name, cb)
}

function parse_htpasswd(input) {
  var result = {}
  input.split('\n').forEach(function(line) {
    if (line) {
      var parsedLine = JSON.parse(line)

      result[parsedLine.user] = parsedLine
    }
  })
  return result
}

function verify_password(user, passwd, hash) {
  if (hash.indexOf('{PLAIN}') === 0) {
    return passwd === hash.substr(7)
  } else if (hash.indexOf('{SHA}') === 0) {
    return crypto.createHash('sha1').update(passwd, 'binary').digest('base64') === hash.substr(5)
  } else if (crypt3) {
    return crypt3(passwd, hash) === hash
  } else {
    return false
  }
}

function add_user_to_htpasswd(body, user, passwd, is_approved) {
  if (user !== encodeURIComponent(user)) {
    var err = Error('username should not contain non-uri-safe characters')
    err.status = 409
    throw err
  }

  if (crypt3) {
    passwd = crypt3(passwd)
  } else {
    passwd = '{SHA}' + crypto.createHash('sha1').update(passwd, 'binary').digest('base64')
  }

  var userData = {
    user: user,
    hash: passwd,
    comment: 'autocreated ' + (new Date()).toJSON(),
    is_approved: is_approved
  }
  var newline = JSON.stringify(userData) + '\n'

  if (body.length && body[body.length-1] !== '\n') newline = '\n' + newline
  return body + newline
}

module.exports.parse_htpasswd = parse_htpasswd
module.exports.verify_password = verify_password
module.exports.add_user_to_htpasswd = add_user_to_htpasswd
module.exports.lock_and_read = lock_and_read
module.exports.unlock_file = unlock_file
