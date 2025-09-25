// import express from "express";

// const app = express();
// app.get("/api/posts/greet", (req, res) => {  
//   const name = req.query.name || "World";  
//   res.send(`Hello, ${name}! Buổi tối vui vẻ `);  
// });

// app.get("/api/posts/sum", (req, res) => {
//   const a = parseFloat(req.query.a);
//   const b = parseFloat(req.query.b);
//   if (isNaN(a) || isNaN(b)) {
//     return res.status(400).send("Invalid numbers provided.");
//   }
//   const sum = a + b;
//   res.send(`The sum of ${a} and ${b} is ${sum}.`);
// });
// app.listen(3000, () => {
//   console.log(`Server is running on port http://localhost:3000`);
// });

import express from "express";
import morgan from "morgan";

import router from "./Router";

const app = express();

// Dùng morgan để log ở chế độ 'dev'
app.use(morgan("dev"));

// Middleware tích hợp để parse JSON: req.body
app.use(express.json());

app.use("/", router);

app.listen(3000, () => {
  console.log(`Server is running on port http://localhost:3000`);
});
