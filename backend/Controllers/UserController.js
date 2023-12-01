const router = require("express").Router();
const User = require("../Models/UserModel");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
const { generateOTP } = require("./OTP/mailOtp");
const VerificationToken = require("../Models/TokenVerificationModel");
const JWTSEC = "cattu123";
const nodemailer = require("nodemailer");

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
    const OTP = generateOTP();
    const verificationToken = await VerificationToken.create({
      user: user._id,
      token: OTP,
    });
    verificationToken.save();
    await user.save();
    const transport = nodemailer.createTransport({
      host: "sandbox.smtp.mailtrap.io",
      port: 2525,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
    });
    transport.sendMail({
      from: "sociaMedia@gmail.com",
      to: user.email,
      subject: "Verify your email using OTP",
      html: `<h1>Your OTP CODE ${OTP}</h1>`,
    });
    res.status(200).json({
      Status: "Pending",
      msg: "Please check your email",
      user: user._id,
    });
    // res.status(200).json({ user, Token });
  }
);
//verify mail

router.post("/verify/email", async (req, res) => {
  const { user, OTP } = req.body;
  const currUser = await User.findById(user);
  if (!currUser) {
    return res.status(400).json("user not found");
  }
  if (currUser.verified == true) {
    return res.status(400).json("user already verified");
  }
  const token = await VerificationToken.findOne({ user: currUser._id });
  if (!token) {
    return res.status(400).json("otp not found");
  }
  const Match = await bcrypt.compareSync(OTP, token.token);
  if (!Match) {
    return res.status(400).json("otp not valid");
  }
  currUser.verified = true;
  await VerificationToken.findByIdAndDelete(token._id);
  await currUser.save();
  const accessToken = jwt.sign(
    {
      id: currUser._id,
      username: currUser.username,
    },
    JWTSEC
  );
  const { password, ...other } = currUser._doc;
  const transport = nodemailer.createTransport({
    host: "smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: process.env.USER,
      pass: process.env.PASS,
    },
  });
  transport.sendMail({
    from: "sociaMedia@gmail.com",
    to: currUser.email,
    subject: "Successfully verify your email",
    html: `Now you can login in social app`,
  });
  return res.status(200).json({ other, accessToken });
});

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
