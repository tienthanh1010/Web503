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
export function getPosts(req, res){
    const { title } = req.query;
    let result = posts;
    if (title) {
        result = posts.filter(p =>
            p.title.toLowerCase().includes(title.toLowerCase())
        );
    }
    if (result.length === 0) {
        return res.status(404).json({ error: "Không tìm thấy sản phẩm" });
    }
    res.json(result);
}
export function getPostsById(req,res){
    const post = posts.find(p => p.id === +req.params.id);
    post ? res.json(post) : res.status(404).json({ error: "Không tìm thấy sản phẩm" });
}
export function addPost(req,res){
    const newPost = { id: posts.length ? Math.max(...posts.map(p => p.id)) + 1 : 1, ...req.body };
    posts.push(newPost);
    res.status(201).json(newPost);
}
export function updatePost(req,res){
    const index = posts.findIndex(p => p.id === +req.params.id);
    if (index === -1) return res.status(404).json({ error: "Không tìm thấy sản phẩm" });
    posts[index] = { ...posts[index], ...req.body, id: posts[index].id };
    res.json(posts[index]);
}
export function deletePost(req,res){
    const index = posts.findIndex(p => p.id === +req.params.id);
    if (index === -1) return res.status(404).json({ error: "Không tìm thấy sản phẩm" });

    const deleted = posts.splice(index, 1);
    res.json({ success: true, message: "Xóa thành công!", deleted });
}
