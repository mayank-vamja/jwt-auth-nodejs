const config = require("config.json");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("_helpers/db");
const Role = require("_helpers/role");
const User = db.User;

// jwt token timeout
const tokenTimeout = "60m";

// refresh token timeout in miliseconds
const refreshTokenTimeout = 7 * 24 * 60 * 60 * 1000;

module.exports = {
  authenticate,
  register,
  refreshToken,
  revokeToken,
  getAll,
  getById,
  getRefreshTokens,
  update,
  delete: _delete,
  getAllNotes,
  compareNotesByIds,
  addUpdateNote,
  getNote,
  updateNote,
  deleteNote,
};

async function authenticate({ username, password, ipAddress }) {
  const user = await User.findOne({ username });

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    throw "Username or password is incorrect";
  }

  // authentication successful so generate jwt and refresh tokens
  const jwtToken = generateJwtToken(user);
  const refreshToken = generateRefreshToken(user, ipAddress);

  // save refresh token
  await refreshToken.save();

  // return basic details and tokens
  return {
    ...basicDetails(user),
    jwtToken,
    refreshToken: refreshToken.token,
  };
}

async function register(userParam, ip) {
  if (await User.findOne({ username: userParam.username })) {
    throw 'Username "' + userParam.username + '" is already taken';
  }

  const user = new User(userParam);
  user.role = Role.User;
  // hash password
  if (userParam.password) {
    user.passwordHash = bcrypt.hashSync(userParam.password, 10);
  }

  // save user
  await user.save();
}

async function update(id, userParam) {
  const user = await User.findById(id);

  // validate
  if (!user) throw "Unauthenticated User.";
  if (
    user.username !== userParam.username &&
    (await User.findOne({ username: userParam.username }))
  ) {
    throw 'Username "' + userParam.username + '" is already taken';
  }

  // hash password if it was entered
  if (userParam.password) {
    userParam.hash = bcrypt.hashSync(userParam.password, 10);
  }

  // copy userParam properties to user
  Object.assign(user, userParam);

  await user.save();

  return { ...basicDetails(user) };
}

async function _delete(id) {
  await User.findByIdAndRemove(id);
}

async function refreshToken({ token, ipAddress }) {
  const refreshToken = await getRefreshToken(token);
  const { user } = refreshToken;

  // replace old refresh token with a new one and save
  const newRefreshToken = generateRefreshToken(user, ipAddress);
  refreshToken.revoked = Date.now();
  refreshToken.revokedByIp = ipAddress;
  refreshToken.replacedByToken = newRefreshToken.token;
  await refreshToken.save();
  await newRefreshToken.save();

  // generate new jwt
  const jwtToken = generateJwtToken(user);

  // return basic details and tokens
  return {
    ...basicDetails(user),
    jwtToken,
    refreshToken: newRefreshToken.token,
  };
}

async function revokeToken({ token, ipAddress }) {
  const refreshToken = await getRefreshToken(token);

  // revoke token and save
  refreshToken.revoked = Date.now();
  refreshToken.revokedByIp = ipAddress;
  await refreshToken.save();
}

async function getAll() {
  const users = await User.find();
  return users.map((x) => basicDetails(x));
}

async function getById(id) {
  const user = await getUser(id);
  return basicDetails(user);
}

async function getRefreshTokens(userId) {
  // check that user exists
  await getUser(userId);

  // return refresh tokens for user
  const refreshTokens = await db.RefreshToken.find({ user: userId });
  return refreshTokens;
}

// helper functions

async function getUser(id) {
  if (!db.isValidId(id)) throw "User not found";
  const user = await User.findById(id);
  if (!user) throw "User not found";
  return user;
}

async function getRefreshToken(token) {
  const refreshToken = await db.RefreshToken.findOne({ token }).populate(
    "user"
  );
  if (!refreshToken || !refreshToken.isActive) throw "Invalid token";
  return refreshToken;
}

function generateJwtToken(user) {
  return jwt.sign({ sub: user.id, id: user.id }, config.secret, {
    expiresIn: tokenTimeout,
  });
}

function generateRefreshToken(user, ipAddress) {
  // create a refresh token that expires in 7 days
  return new db.RefreshToken({
    user: user.id,
    token: randomTokenString(),
    expires: new Date(Date.now() + refreshTokenTimeout),
    createdByIp: ipAddress,
  });
}

function randomTokenString() {
  return crypto.randomBytes(40).toString("hex");
}

function basicDetails(user) {
  const { id, firstName, lastName, username, dp, role } = user;
  return { id, firstName, lastName, username, dp, role };
}

/// NOTES ///

async function getAllNotes(id) {
  const user = await User.findById(id);
  if (!user) throw "Unauthenticated User.";
  return user.notes;
}

async function compareNotesByIds(id, noteIds) {
  const user = await User.findById(id);
  if (!user) throw "Unauthenticated User.";
  if (noteIds.length == 0) throw "Empty list requested.";
  const dbNoteIds = user.notes.map((n) => n.id);
  const filteredIds = dbNoteIds.filter((i) => !noteIds.includes(i));
  const filteredNotes = user.notes.filter((n) => filteredIds.includes(n.id));
  return filteredNotes;
}

async function addUpdateNote(id, note) {
  const user = await User.findById(id);
  if (!user) throw "Unauthenticated User.";
  const noteIndex = user.notes.findIndex((i) => i.id == note.id);
  if (noteIndex === -1) {
    user.notes.push(note);
    await user.save();
    return { success: true, message: "Note added successfully" };
  } else {
    const newNote = { ...user.notes[noteIndex], ...note };
    user.notes[noteIndex] = newNote;
    user.markModified("notes");
    await user.save();
    return { success: true, message: "Note updated successfully" };
  }
}

async function getNote(id, noteId) {
  const user = await User.findById(id);
  if (!user) throw "Unauthenticated User.";
  const noteDoc = user.notes.filter((i) => i.id == noteId)[0];
  if (!noteDoc) throw "Note not found.";
  return { success: true, note: noteDoc };
}

async function updateNote(id, noteId, note) {
  const user = await User.findById(id);
  if (!user) throw "Unauthenticated User.";
  const noteIndex = user.notes.findIndex((i) => i.id == noteId);
  if (!noteIndex) throw "Note not found to update.";
  const newNote = { ...user.notes[noteIndex], ...note };
  user.notes[noteIndex] = newNote;
  user.markModified("notes");
  await user.save();
  return { success: true, newNote };
}

async function deleteNote(id, noteId) {
  const user = await User.findById(id);
  if (!user) throw "Unauthenticated User.";
  user.notes = user.notes.filter((i) => i.id != noteId);
  await user.save();
}
