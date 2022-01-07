const jwt = require("jsonwebtoken");

function generateAccessToken(id, email) {
    return jwt.sign(
        { user_id: id, email },
        process.env.ACCESS_TOKEN_SECRECT,
        { expiresIn: "20s" }
    );
}


function generateRefreshToken(id, email) {
    return jwt.sign(
        { user_id: id, email },
        process.env.REFRESH_TOKEN_SECRECT,
        { expiresIn: "2m" }
    );
}

module.exports = { generateAccessToken, generateRefreshToken };