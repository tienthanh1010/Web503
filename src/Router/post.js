import express from "express";

const postRouter = express.Router();

let posts = [
  {
    id: 1,
    title: "Ryzen 7 9800X3D",
    brand: "AMD",
    price: 450,
    manufactureDate: "2024-05-20",
    active: true,
    description: "CPU hiệu năng cao với 3D V-Cache, phù hợp gaming và đồ họa"
  },
  {
    id: 2,
    title: "Intel Core i7-13700K",
    brand: "Intel",
    price: 419,
    manufactureDate: "2022-10-20",
    active: true,
    description:
      "Intel Core i7 thế hệ 13, 16 nhân 24 luồng, xung nhịp tối đa 5.4GHz, socket LGA1700."
  }
];

// Tạo biến đếm id (bằng id lớn nhất hiện có)
let nextId = posts.length > 0 ? Math.max(...posts.map(p => p.id)) + 1 : 1;

// GET /api/posts - Lấy danh sách
postRouter.get("/", (req, res) => {
  res.json(posts);
});

// GET /api/posts/:id - Lấy chi tiết theo id
postRouter.get("/:id", (req, res) => {
  const post = posts.find((p) => p.id === parseInt(req.params.id));
  if (!post) {
    return res.status(404).json({ error: "Không tìm thấy bài viết với ID này" });
  }
  res.json(post);
});

// POST /api/posts - Thêm bài viết mới
postRouter.post("/", (req, res) => {
  const { title, brand, price, manufactureDate, active, description } = req.body;

  const newPost = {
    id: nextId++, // id tự tăng
    title,
    brand,
    price,
    manufactureDate,
    active,
    description,
  };

  posts.push(newPost);
  res.status(201).json(newPost);
});

// PUT /api/posts/:id - Cập nhật bài viết
postRouter.put("/:id", (req, res) => {
  const post = posts.find((p) => p.id === parseInt(req.params.id));
  if (!post) return res.status(404).json({ error: "Post not found" });

  const { title, brand, price, manufactureDate, active, description } = req.body;

  post.title = title ?? post.title;
  post.brand = brand ?? post.brand;
  post.price = price ?? post.price;
  post.manufactureDate = manufactureDate ?? post.manufactureDate;
  post.active = active ?? post.active;
  post.description = description ?? post.description;

  res.json(post);
});

// DELETE /api/posts/:id - Xóa bài viết
postRouter.delete("/:id", (req, res) => {
  const index = posts.findIndex((p) => p.id === parseInt(req.params.id));
  if (index === -1) return res.status(404).json({ error: "Post not found" });

  posts.splice(index, 1);
  res.json({ success: true, message: "Xóa thành công!" });
});

export default postRouter;
