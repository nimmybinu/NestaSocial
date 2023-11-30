const router = require("express").Router();
const User = require("../Models/UserModel");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
const JWTSEC = "cattu123";
//Register
router.post(
  "/create/user",
  body("email").isEmail(),
  body("password").isLength({ min: 4 }),
  body("username").isLength({ min: 3 }),
  body("phonenumber").isLength({ min: 10 }),
  async (req, res) => {
    const error = validationResult(req);
    if (!error.isEmpty()) {
      return res.status(400).json("some error occured");
    }

    let user = await User.findOne({ email: req.body.email });
    if (user) {
      return res.status(200).json("email id already exist");
    }
    const salt = await bcrypt.genSalt(10);
    const securepass = await bcrypt.hash(req.body.password, salt);

    user = await User.create({
      username: req.body.username,
      email: req.body.email,
      password: securepass,

      profile: req.body.profile,
      phonenumber: req.body.phonenumber,
    });
    const Token = jwt.sign(
      {
        id: user._id,
        username: user.username,
      },
      JWTSEC
    );
    await user.save();
    res.status(200).json({ user, Token });
  }
);

//login

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(400).json("User doesn't found");
    }
    const Comparepassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!Comparepassword) {
      return res.status(400).json("Password error");
    }
    const accessToken = jwt.sign(
      {
        id: user._id,
        username: user.username,
      },
      JWTSEC
    );
    const { password, ...other } = user._doc;
    res.status(200).json({ other, accessToken });
  } catch (err) {
    res.status(500).json("internal server error");
  }
});
module.exports = router;
