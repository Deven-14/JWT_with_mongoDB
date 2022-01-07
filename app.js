require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const {getNewAccessToken, getNewRefreshToken} = require("./helpers/token");

const app = express();

app.use(express.json());


// importing user context
const User = require("./model/user");

// Register
app.post("/register", async (req, res) => {

    // Our register logic starts here
    try {
      // Get user input
      const { first_name, last_name, email, password } = req.body;
  
      // Validate user input
      if (!(email && password && first_name && last_name)) {
        res.status(400).send("All input is required");
      }
  
      // check if user already exist
      // Validate if user exist in our database
      const oldUser = await User.findOne({ email });
  
      if (oldUser) {
        return res.status(409).send("User Already Exist. Please Login");
      }
  
      //Encrypt user password
      encryptedPassword = await bcrypt.hash(password, 10);
  
      // Create user in our database
      const user = await User.create({
        first_name,
        last_name,
        email: email.toLowerCase(), // sanitize: convert email to lowercase
        password: encryptedPassword,
      });
  
      // Create token
      const token = getNewAccessToken(user._id, email);
      const refreshToken = getNewRefreshToken(user._id, email);
      // save user token
      user.token = token;
      user.refreshToken = refreshToken;
  
      // return new user
      res.status(201).json(user);
    } catch (err) {
      console.log(err);
    }
    // Our register logic ends here
  });

// Login
app.post("/login", async (req, res) => {

    // Our login logic starts here
    try {
      // Get user input
      const { email, password } = req.body;
  
      // Validate user input
      if (!(email && password)) {
        res.status(400).send("All input is required");
      }
      // Validate if user exist in our database
      const user = await User.findOne({ email });
  
      if (user && (await bcrypt.compare(password, user.password))) {
        // Create token
        // Create token
        const token = getNewAccessToken(user._id, email);
        const refreshToken = getNewRefreshToken(user._id, email);
        // save user token
        user.token = token;
        user.refreshToken = refreshToken;

        // user
        res.status(200).json(user);
      }
      else {
        res.status(400).send("Invalid Credentials");
      }
    } catch (err) {
      console.log(err);
    }
    // Our register logic ends here
});


app.post("/refreshToken", (req, res) => {
  const token = req.body.refreshToken || req.query.refreshToken;// || req.headers["x-access-token"];

  if (!token) {
    return res.status(403).send("A token is required for authentication"); // return is important here
  }
  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRECT);
    const { user_id, email } = decoded;
    const accessToken = getNewAccessToken(user_id, email);
    res.status(200).json({ accessToken });

  } catch (err) {
    res.status(401).send("Invalid Refresh Token, Login Again");
  }
});

const auth = require("./middleware/auth");

app.post("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome 🙌 ");
});  


module.exports = app;