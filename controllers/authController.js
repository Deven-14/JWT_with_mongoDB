const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { generateAccessToken, generateRefreshToken } = require("../helpers/token");
const User = require("../models/user"); // importing user context


exports.register = async (req, res) => {

    try {

      const { first_name, last_name, email, password } = req.body;
  
      if (!(email && password && first_name && last_name)) {
        return res.status(400).json({ error: "All Inputs are Required" });
      }
  
      const oldUser = await User.findOne({ email });
  
      if (oldUser) {
        return res.status(409).json({ error: "User Already Exists, Please Login" });
      }
  
      encryptedPassword = await bcrypt.hash(password, 10);
  
      const user = await User.create({
        first_name,
        last_name,
        email: email.toLowerCase(), // sanitize: convert email to lowercase
        password: encryptedPassword,
      });
  
      const token = generateAccessToken(user._id, email);
      const refreshToken = generateRefreshToken(user._id, email);
      user.token = token;
      user.refreshToken = refreshToken;
  
      res.status(201).json(user);

    } catch (err) {
      console.log(err);
      res.status(500).json({ error: "Internal Server Error" });
    }
};

exports.login = async (req, res) => {

    try {
      
      const { email, password } = req.body;
  
      if (!(email && password)) {
        return res.status(400).json({ error: "All Inputs are Required" });
      }

      const user = await User.findOne({ email });
  
      if (user && (await bcrypt.compare(password, user.password))) {

        const token = generateAccessToken(user._id, email);
        const refreshToken = generateRefreshToken(user._id, email);
        user.token = token;
        user.refreshToken = refreshToken;

        res.status(200).json(user);
      } else {
        res.status(401).json({ error: "Invalid Credentials" });
      }
    } catch (err) {
      console.log(err);
      res.status(500).json({ error: "Internal Server Error" });
    }

};


exports.refreshToken = async (req, res) => {
  
    const token = req.body.refreshToken || req.query.refreshToken;// || req.headers["x-access-token"];
  
    if (!token) {
      return res.status(400).json({ error: "Access denied, Token missing!" });
    }
    try {
  
      const { email, password } = req.body;
    
      if (!(email && password)) {
        return res.status(400).json({ error: "All Inputs are Required" });
      }
  
      const user = await User.findOne({ email });
  
      if (user && (await bcrypt.compare(password, user.password))) {
  
        const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRECT);
        const { user_id, email } = decoded;
        const accessToken = generateAccessToken(user_id, email);
        res.status(200).json({ accessToken });
  
      } else {
        res.status(401).json({ error: "Invalid Credentials" });
      }
  
    } catch (err) {
      return res.status(401).json({ error: "Refresh Token Expired, Login Again" });
    }
    
};