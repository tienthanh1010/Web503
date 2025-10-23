import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Joi from "joi";

const app = express();
app.use(express.json());

mongoose.connect("mongodb://localhost:27017/kientra_nodejs_fa25")
  .then(() => console.log(" Connected to MongoDB"))
  .catch(err => console.error(" MongoDB error:", err));


const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "user" },
});
const User = mongoose.model("User", userSchema);

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

app.post("/auth/register", async (req, res) => {
  try {
    const { error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const { email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email đã tồn tại" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashed });
    res.status(201).json({ message: "Đăng ký thành công", user });
  } catch (err) {
    res.status(500).json({ message: "Lỗi server", err });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Sai email hoặc mật khẩu" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Sai email hoặc mật khẩu" });

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      "secret_key",
      { expiresIn: "2h" }
    );
    res.json({ message: "Đăng nhập thành công", token });
  } catch (err) {
    res.status(500).json({ message: "Lỗi server", err });
  }
});

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer "))
    return res.status(401).json({ message: "Không có token" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, "secret_key", (err, user) => {
    if (err) return res.status(403).json({ message: "Token không hợp lệ" });
    req.user = user;
    next();
  });
};


const courseSchema = new mongoose.Schema({
  courseName: { type: String, required: true },
  views: { type: Number, required: true, min: 1 },
  thumbnail: { type: String, required: true },
  note: String,
  category: { type: String, required: true },
});
const Course = mongoose.model("Course", courseSchema);

const courseJoi = Joi.object({
  courseName: Joi.string().required(),
  views: Joi.number().min(1).required(),
  thumbnail: Joi.string().uri().required(),
  note: Joi.string().optional(),
  category: Joi.string().required(),
});

app.get("/courses", verifyToken, async (req, res) => {
  const data = await Course.find();
  res.json(data);
});

app.get("/courses/:id", verifyToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Không tìm thấy khóa học" });
    res.json(course);
  } catch {
    res.status(400).json({ message: "ID không hợp lệ" });
  }
});

app.post("/courses", verifyToken, async (req, res) => {
  const { error } = courseJoi.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });
  const newCourse = await Course.create(req.body);
  res.status(201).json(newCourse);
});

app.put("/courses/:id", verifyToken, async (req, res) => {
  const { error } = courseJoi.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  const updated = await Course.findByIdAndUpdate(req.params.id, req.body, { new: true });
  if (!updated) return res.status(404).json({ message: "Không tìm thấy khóa học" });
  res.json(updated);
});

app.delete("/courses/:id", verifyToken, async (req, res) => {
  const deleted = await Course.findByIdAndDelete(req.params.id);
  if (!deleted) return res.status(404).json({ message: "Không tìm thấy khóa học" });
  res.json({ message: "Đã xóa thành công" });
});


app.listen(3000, () => console.log("🚀 Server running: http://localhost:3000"));
