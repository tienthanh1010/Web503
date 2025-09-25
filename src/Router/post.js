import express from "express";
import {getPosts} from '../controllers/post';
import {getPostsById} from '../controllers/post';
import {addPost} from '../controllers/post';
import {updatePost} from '../controllers/post';
import {deletePost} from '../controllers/post';

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
    description: "Intel Core i7 thế hệ 13, 16 nhân 24 luồng, xung nhịp tối đa 5.4GHz, socket LGA1700."
  }
];
// Biến id tự tăng
let nextId = posts.length ? Math.max(...posts.map(p => p.id)) + 1 : 1;
// Lấy danh sách
postRouter.get("/", getPosts);
// Lấy chi tiết theo id
postRouter.get("/:id", getPostsById);
// Thêm mới
postRouter.post("/", addPost);
// Cập nhật
postRouter.put("/:id", updatePost);
// Xóa
postRouter.delete("/:id", deletePost);

export default postRouter;
