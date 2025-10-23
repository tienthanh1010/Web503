import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

// Kết nối MongoDB
mongoose
  .connect("mongodb://localhost:27017/kiemtra_nodejs_fa25")
  .then(() => console.log(" Connected to MongoDB"))
  .catch((err) => console.error(" Could not connect:", err));

const courseSchema = new mongoose.Schema({
  courseName: String,
  views: Number,
  thumbnail: String,
  note: String,
  category: String,
});
const Course = mongoose.model("Course", courseSchema);


const validateToken = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.json("Thiếu token");

  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, "khoa-bi-mat");
    req.user = decoded;
    next();
  } catch (error) {
    res.json("Token không hợp lệ hoặc hết hạn");
  }
};

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    role: { type: String, enum: ["user", "admin"], default: "user" },
  });
  const User = mongoose.model("User", userSchema);

app.post("/auth/register", async (req, res) => {
  try {
    const existed = await User.findOne({ email: req.body.email });
    if (existed) return res.json("Email đã tồn tại");

    const hash = await bcrypt.hash(req.body.password, 10);
    const user = await User.create({ email: req.body.email, password: hash });
    res.json(user);
  } catch (err) {
    res.json(err.message);
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.json("Không tồn tại email này");

    const match = await bcrypt.compare(req.body.password, user.password);
    if (!match) return res.json("Sai mật khẩu");

    const token = jwt.sign({ id: user._id }, "khoa-bi-mat", { expiresIn: "1d" });
    res.json({ message: "Đăng nhập thành công", token });
  } catch (err) {
    res.json(err.message);
  }
});

app.get("/courses", async (req, res) => {
  const data = await Course.find();
  res.json(data);
});

app.get("/courses/:id", async (req, res) => {
  const data = await Course.findById(req.params.id);
  if (!data) return res.json("Không tìm thấy");
  res.json(data);
});

app.post("/courses", validateToken, async (req, res) => {
  const data = await Course.create(req.body);
  res.json(data);
});

app.put("/courses/:id", validateToken, async (req, res) => {
  const data = await Course.findByIdAndUpdate(req.params.id, req.body, { new: true });
  if (!data) return res.json("Không tìm thấy");
  res.json(data);
});

app.delete("/courses/:id", validateToken, async (req, res) => {
  const data = await Course.findByIdAndDelete(req.params.id);
  if (!data) return res.json("Không tìm thấy");
  res.json("Xóa thành công");
});

app.listen(3000, () => console.log("🚀 Server running: http://localhost:3000"));
