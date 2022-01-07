const jwt = require("jsonwebtoken");

function getNewAccessToken(id, email) {
    return jwt.sign(
        { user_id: id, email },
        process.env.ACCESS_TOKEN_SECRECT,
        { expiresIn: "20s" }
    );
}


function getNewRefreshToken(id, email) {
    return jwt.sign(
        { user_id: id, email },
        process.env.REFRESH_TOKEN_SECRECT,
        { expiresIn: "2m" }
    );
}

module.exports = {getNewAccessToken, getNewRefreshToken};