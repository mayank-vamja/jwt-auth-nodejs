require("rootpath")();
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const errorHandler = require("_middleware/error-handler");

// create test user in db on startup if required
app.use(bodyParser.json({ limit: "4mb" }));
app.use(bodyParser.urlencoded({ limit: "4mb", extended: true }));
app.use(cookieParser());

// allow cors requests from any origin and with credentials
app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));

// api routes
app.use("/", require("./users/users.controller"));

// global error handler
app.use(errorHandler);

// start server
const port = process.env.NODE_ENV === "production" ? process.env.PORT || 80 : 4000;
app.listen(port, () => {
  console.log("Server listening on port " + port);
});
