const express = require("express");
const authRouter = require("./authRouter");
const router = express.Router();
const auth = require("../middlewares/auth");

router.use("/auth", authRouter);

router.post("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome 🙌 ");
});  

module.exports = router;