import { Router } from "express";
import postRouter from "./post";
import userRouter from "./user";
import productRouter from "./product";

const router = Router();

// Định nghĩa route GET /

// .get : Method HTTP: GET
// "/": Endpoint API - URL
// function (req, res) :
// req: du lieu gui tu client (Frontend)
// res: du lieu server tra ve cho client (FE)
// app.get("/", (req, res) => {
//   res.send("Hello, chao cac ban");
// });

//   localhost":3000/?name=Teo
router.get("/", (req, res) => {
  console.log(req.query?.name);
  res.send("Hello, Word: " + req.query?.name);
});

// gom api posts
router.use("/api/posts", postRouter);

// gom api users
router.use("/api/users", userRouter);

// gom api products
router.use("/api/products", productRouter);

export default router;
