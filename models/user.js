// Requiring mongoose and bcrypt, set a schema
var mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    bcrypt = require('bcryptjs');

// Creates a schema for the user
var userSchema = new Schema({
  created: { type: Date },
  updated: { type: Date },
  email: { type: String, unique: true, lowercase: true },
  password: { type: String, select: false },
  displayName: String,
  // TODO #12
  picture: String
});


userSchema.pre('save', function (next) {
  // set created and updated
  // gives new submissions a time of creation
  now = new Date();
  this.updated = now;
  if (!this.created) {
    this.created = now;
  }

  // encrypt password
  // check if password has been modified, if not go to the next user
  var user = this;
  if (!user.isModified('password')) {
    return next();
  }
  // this is the encryption function?
  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(user.password, salt, function (err, hash) {
      user.password = hash;
      next();
    });
  });
});

// check the password against the password stored in bcrypt
userSchema.methods.comparePassword = function (password, done) {
  bcrypt.compare(password, this.password, function (err, isMatch) {
    done(err, isMatch);
  });
};

// export the model in a User variable
var User = mongoose.model('User', userSchema);
module.exports = User;
