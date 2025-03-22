const express = require("express");
const { registerUser, loginUser, getLoggedInUser } = require("../controllers/userController");
const authMiddleware = require("../config/jwt");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/me", authMiddleware, getLoggedInUser);

module.exports = router;
