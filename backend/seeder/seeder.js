import mongoose from "mongoose";
import products from "./data.js";
import Product from "../models/product.js"

const seedProducts = async () => {
  try {
    await mongoose.connect("DB_URI = mongodb+srv://rogeriocabral2002:ro102030@loja.5rs0h.mongodb.net/?retryWrites=true&w=majority&appName=Loja");

    await Product.deleteMany();
    console.log("Produtos deletados");

    await Product.insertMany(products);
    console.log("Produtos adicionados");

    process.exit();

  } catch (error) {
    console.log(error.message);
    process.exit();    
  }
};

seedProducts();