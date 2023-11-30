const express = require("express");
const app = express();
const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();
const userRouter = require("./Controllers/UserController");
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("db connected");
  })
  .catch(() => {
    console.log("something went wrong");
  });
app.use(express.json());
app.use("/api/user", userRouter);
app.listen(5000, () => {
  console.log("server is running");
});
