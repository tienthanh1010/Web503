import { Router } from "express";

const userRouter = Router();

userRouter.get("/", (req, res) => {
  res.send("users");
});

// endpoint: api/users/greet
userRouter.get("/user", (req, res) => {
  res.send("user greet");
});

export default userRouter;
