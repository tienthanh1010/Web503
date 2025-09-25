import { Router } from "express";
const productRouter = Router();
const logRequestTime = (req, res, next) => {
  console.log(
    `[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`
  );
  next();
};
productRouter.use(logRequestTime);
const products = [
  { id: 1, name: "Laptop", price: 1000 },
  { id: 2, name: "Phone", price: 500 },
  { id: 3, name: "Tablet", price: 300 },
];
productRouter.get("/", (req, res) => {
  res.json(products);
});
productRouter.get("/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const product = products.find((p) => p.id === id);

  if (!product) {
    return res.status(404).json({
      message: "Không tìm thấy sản phẩm với ID này",
    });
  }

  res.json(product);
});
productRouter.get("/search", (req, res) => {
  const { name } = req.query;
  if (!name) {
    return res.status(400).json({ message: "Vui lòng nhập tên để tìm kiếm" });
  }
  const results = products.filter((p) =>
    p.name.toLowerCase().includes(name.toLowerCase())
  );

  res.json(results);
});

export default productRouter;
