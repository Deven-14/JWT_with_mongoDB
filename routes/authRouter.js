require("dotenv").config();
require("../config/database").connect();
const express = require("express");
// const authController = require("../controllers/authController");
const { register, login, refreshToken } = require("../controllers/authController");

const router = express.Router();

router.use(express.json());


router.post("/register", register);


router.post("/login", login);


router.post("/refreshToken", refreshToken);

module.exports = router;