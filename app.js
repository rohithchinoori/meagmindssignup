const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { check, validationResult } = require("express-validator");
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./database.db");
const cors = require("cors");

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

// Create the 'users' table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);
});

// Registration route
app.post(
  "/api/auth/register",
  [
    check("username", "Username is required").notEmpty(),
    check("password", "Password is required").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, password } = req.body;

      // Check if the username is already taken
      const existingUser = await new Promise((resolve, reject) => {
        db.get(
          "SELECT * FROM users WHERE username = ?",
          [username],
          (err, row) => {
            if (err) {
              reject(err);
              return;
            }
            resolve(row);
          }
        );
      });

      if (existingUser) {
        return res.status(400).json({ msg: "Username is already taken" });
      }

      // Hash the password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Insert the user into the 'users' table
      db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword],
        (err) => {
          if (err) {
            return res.status(500).json({ msg: "Failed to register user" });
          }

          const payload = {
            user: {
              id: this.lastID,
            },
          };

          jwt.sign(
            payload,
            "yourSecretKey", // Replace with your own secret key
            { expiresIn: 3600 }, // Token expiration time
            (err, token) => {
              if (err) throw err;
              res.json({ token });
            }
          );
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

// Login route
app.post(
  "/api/auth/login",
  [
    check("username", "Username is required").notEmpty(),
    check("password", "Password is required").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, password } = req.body;

      // Retrieve the user from the 'users' table
      db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
          if (err) {
            return res.status(500).json({ msg: "Server error" });
          }

          if (!user) {
            return res.status(400).json({ msg: "Invalid credentials" });
          }

          // Compare the provided password with the hashed password
          const isMatch = await bcrypt.compare(password, user.password);

          if (!isMatch) {
            return res.status(400).json({ msg: "Invalid credentials" });
          }

          const payload = {
            user: {
              id: user.id,
            },
          };

          jwt.sign(
            payload,
            "yourSecretKey", // Replace with your own secret key
            { expiresIn: 3600 }, // Token expiration time
            (err, token) => {
              if (err) throw err;
              res.json({ token });
            }
          );
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
