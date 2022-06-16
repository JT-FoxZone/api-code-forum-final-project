var express = require("express");
var cors = require("cors");
var app = express();
var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();
const bcrypt = require("bcrypt");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = "Register-Code-Forum";

const mysql = require("mysql2");
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "code-forum",
});

app.use(cors());

app.post("/register", jsonParser, function (req, res, next) {
  const { email, password, fname, lname } = req.body;

  bcrypt.genSalt(saltRounds, function (err, salt) {
    bcrypt.hash(password, salt, function (err, hash) {
      connection.execute(
        "INSERT INTO `users` (email, password, fname, lname) VALUES (?,?,?,?)",
        [email, hash, fname, lname],
        function (err, results, fields) {
          if (err) {
            res.json({ status: "error", message: err });
            return;
          }
          res.json({ status: "ok" });
        }
      );
    });
  });
});

app.post("/login", jsonParser, function (req, res, next) {
  connection.execute(
    "SELECT * FROM users WHERE email=?",
    [req.body.email],
    function (err, users, fields) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      if (users.length == 0) {
        res.json({ status: "error", message: "no user found" });
        return;
      }

      bcrypt.compare(
        req.body.password,
        users[0].password,
        function (err, isLogin) {
          if (isLogin) {
            var token = jwt.sign(
              {
                email: users[0].email,
                name: users[0].fname,
                id: users[0].user_id,
              },
              secret,
              {
                expiresIn: "1h",
              }
            );
            res.json({ status: "ok", message: "login success", token });
          } else {
            res.json({ status: "error", message: "login failed" });
          }
        }
      );
    }
  );
});

app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
  } catch (error) {
    res.json({ status: "error", message: error.message });
  }
});

app.get("/all-users", jsonParser, function (req, res) {
  connection.query("SELECT * FROM `users`", function (err, results) {
    res.json(results);
  });
});

app.get("/category", jsonParser, function (req, res) {
  connection.query("SELECT * FROM `category`", function (err, results) {
    res.json(results);
  });
});

app.get("/category/:id", jsonParser, function (req, res) {
  const id = req.params.id;
  connection.query(
    "SELECT * FROM `category` WHERE `category_id` = ?",
    [id],
    function (err, results) {
      res.json(results);
    }
  );
});

app.get("/users/:id", function (req, res, next) {
  const id = req.params.id;
  connection.query(
    "SELECT * FROM `users` WHERE `user_id` = ?",
    [id],
    function (err, user) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok", user });
    }
  );
});

app.get("/forum/:category_id", function (req, res, next) {
  const category_id = req.params.category_id;
  connection.query(
    "SELECT post.post_id, post.title, post.datetime, users.fname FROM post INNER JOIN users ON post.user_id=users.user_id WHERE post.category_id = ?",
    [category_id],
    function (err, results) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok", results });
    }
  );
});

app.get("/post/:post_id", function (req, res, next) {
  const category_id = req.params.post_id;
  connection.query(
    "SELECT post.title, post.content, post.datetime, users.fname FROM post INNER JOIN users ON post.user_id=users.user_id WHERE post.post_id = ?;",
    [category_id],
    function (err, results) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok", results });
    }
  );
});

app.put("/users", jsonParser, function (req, res, next) {
  const { email, fname, lname, id } = req.body;
  connection.query(
    "UPDATE `users` SET `email` = ?, `fname` = ?, `lname` = ? WHERE `users`.`user_id` = ?;",
    [email, fname, lname, id],
    function (err, results) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok" });
    }
  );
});

app.post("/post", jsonParser, function (req, res, next) {
  const { title, content, datetime, category_id, user_id } = req.body;
  connection.query(
    "INSERT INTO `post` (`title`, `content`, `datetime`, `category_id`, `user_id`) VALUES (?, ?, ?, ?, ?);",
    [title, content, datetime, category_id, user_id],
    function (err, results) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok" });
    }
  );
});

app.post("/comment", jsonParser, function (req, res, next) {
  const { comment, post_id, datetime, user_id } = req.body;
  connection.query(
    "INSERT INTO `comment` (`comment`, `post_id`, `datetime`, `user_id`) VALUES (?, ?, ?, ?);",
    [comment, post_id, datetime, user_id],
    function (err, results) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok" });
    }
  );
});

app.get("/comment/:post_id", function (req, res, next) {
  const post_id = req.params.post_id;
  connection.query(
    "SELECT comment.comment_id, comment.comment, comment.datetime, users.fname FROM comment INNER JOIN users ON comment.user_id=users.user_id WHERE comment.post_id = ?;",
    [post_id],
    function (err, results) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok", results });
    }
  );
});

app.listen(7000, jsonParser, function () {
  console.log("CORS-enabled web server listening on port 7000");
});
