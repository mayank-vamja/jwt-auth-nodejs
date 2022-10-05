const express = require("express");
const router = express.Router();
const Joi = require("@hapi/joi");
const validateRequest = require("_middleware/validate-request");
const authorize = require("_middleware/authorize");
const Role = require("_helpers/role");
const userService = require("./user.service");

// routes
router.post("/login", authenticateSchema, authenticate);
router.post("/signup", register);

router.get("/", authorize(Role.Admin), getAll);

router.post("/refresh-token", refreshToken);
router.post("/revoke-token", authorize(), revokeTokenSchema, revokeToken);
router.get("/:id/refresh-tokens", authorize(), getRefreshTokens);

router.get("/profile", authorize(), getCurrent); // FOR USER
router.get("/profile/:id", authorize(Role.Admin), getById); // FOR ADMIN
router.put("/profile/:id", authorize(), update);
router.delete("/profile/:id", authorize(), _delete);

// Only User can read|write notes.
router.get("/notes", authorize(Role.User), getAllNotes);
router.post(
  "/notes/get-unavailable",
  authorize(Role.User),
  compareNotesWithList
);
router.post("/notes/add-update", authorize(Role.User), addUpdateNote);
router
  .route("/notes/:noteId")
  .get(authorize(Role.User), getNoteById)
  .put(authorize(Role.User), updateNoteById)
  .delete(authorize(Role.User), deleteNoteById);

module.exports = router;

function authenticateSchema(req, res, next) {
  const schema = Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function authenticate(req, res, next) {
  const { username, password } = req.body;
  const ipAddress = req.ip;
  userService
    .authenticate({ username, password, ipAddress })
    .then(({ refreshToken, ...user }) => {
      setTokenCookie(res, refreshToken);
      res.json({ ...user, refreshToken });
    })
    .catch(next);
}

function register(req, res, next) {
  userService
    .register(req.body, req.ip)
    .then(() =>
      res.json({ success: true, message: "User sign up successfull." })
    )
    .catch(next);
}

function refreshToken(req, res, next) {
  const token =
    req.cookies && req.cookies.refreshToken
      ? req.cookies.refreshToken
      : req.body.token;
  const clientRefreshToken = req.body.token;
  const serverRefreshToken = (req.cookies && req.cookies.refreshToken) ?? "";
  const ipAddress = req.ip;
  userService
    .refreshToken({ token, ipAddress })
    .then(({ refreshToken, ...user }) => {
      setTokenCookie(res, refreshToken);
      res.json({ ...user, refreshToken });
    })
    .catch(next);
}

function revokeTokenSchema(req, res, next) {
  const schema = Joi.object({
    token: Joi.string().empty(""),
  });
  validateRequest(req, next, schema);
}

function revokeToken(req, res, next) {
  // accept token from request body or cookie
  const token = req.body.token || req.cookies.refreshToken;
  const ipAddress = req.ip;

  if (!token) return res.status(400).json({ message: "Token is required" });

  // users can revoke their own tokens and admins can revoke any tokens
  if (!req.user.ownsToken(token) && req.user.role !== Role.Admin) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  userService
    .revokeToken({ token, ipAddress })
    .then(() => res.json({ message: "Token revoked" }))
    .catch(next);
}

function getAll(req, res, next) {
  userService
    .getAll()
    .then((users) => res.json(users))
    .catch(next);
}

function getById(req, res, next) {
  // regular users can get their own record and admins can get any record
  if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  userService
    .getById(req.params.id)
    .then((user) => (user ? res.json(user) : res.sendStatus(404)))
    .catch(next);
}

function getRefreshTokens(req, res, next) {
  // users can get their own refresh tokens and admins can get any user's refresh tokens
  if (req.params.id !== req.user.id && req.user.role !== Role.Admin) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  userService
    .getRefreshTokens(req.params.id)
    .then((tokens) => (tokens ? res.json(tokens) : res.sendStatus(404)))
    .catch(next);
}

// helper functions

function setTokenCookie(res, token) {
  // create http only cookie with refresh token that expires in 7 days
  const cookieOptions = {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  };
  res.cookie("refreshToken", token, cookieOptions);
}

/// PROFILE ///

function getCurrent(req, res, next) {
  userService
    .getById(req.user.id)
    .then((user) => (user ? res.json(user) : res.sendStatus(404)))
    .catch(() => res.sendStatus(404));
}

function update(req, res, next) {
  userService
    .update(req.params.id, req.body)
    .then(() => res.json({ success: true, message: "Updated Successfully." }))
    .catch((err) => next(err));
}

function _delete(req, res, next) {
  userService
    .delete(req.params.id)
    .then(() => res.json({}))
    .catch((err) => next(err));
}

/// NOTES ///

function getAllNotes(req, res, next) {
  userService
    .getAllNotes(req.user.id)
    .then((notes) => res.json({ success: true, notes }))
    .catch((err) => next(err));
}

function compareNotesWithList(req, res, next) {
  userService
    .compareNotesByIds(req.user.id, req.body.notes)
    .then((notes) => res.json({ success: true, notes }))
    .catch((err) => next(err));
}

function addUpdateNote(req, res, next) {
  userService
    .addUpdateNote(req.user.id, req.body)
    .then((data) => res.json(data))
    .catch((err) => next(err));
}

function getNoteById(req, res, next) {
  userService
    .getNote(req.user.id, req.params.noteId)
    .then((note) => (note ? res.json(note) : res.sendStatus(404)))
    .catch((err) => next(err));
}

function updateNoteById(req, res, next) {
  userService
    .updateNote(req.user.id, req.params.noteId, req.body)
    .then((data) => res.json(data))
    .catch((err) => next(err));
}

function deleteNoteById(req, res, next) {
  userService
    .deleteNote(req.user.id, req.params.noteId)
    .then(() =>
      res.json({ success: true, message: "Note removed successfully." })
    )
    .catch((err) => next(err));
}
