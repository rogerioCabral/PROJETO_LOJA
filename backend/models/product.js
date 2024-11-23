import mongoose from "mongoose";

const productSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Por favor insira o nome do produto"],
      maxLength: [200, "O nome do produto não pode exceder 200 caracteres"],
    },
    price: {
      type: Number,
      required: [true, "Por favor insira o preço do produto"],
      maxLength: [5, "O preço do produto não pode exceder 5 dígitos"],
    },
    description: {
      type: String,
      required: [true, "Por favor insira a descrição do produto"],
    },
    ratings: {
      type: Number,
      default: 0,
    },
    images: [
      {
        public_id: {
          type: String,
          required: true,
        },
        url: {
          type: String,
          required: true,
        },
      },
    ],
    category: {
      type: String,
      required: [true, "Por favor, insira a categoria do produto"],
      enum: {
        values: [
          "Eletrônicos",
          "Câmeras",
          "Notebooks",
          "Acessórios",
          "Headphones",
          "Alimentação",
          "Livros",
          "Sportes",
          "Jardim",
          "Casa",
        ],
        message: "Por favor, selecione a categoria do produto",
      },
    },
    seller: {
      type: String,
      required: [true, "Por favor, insira o vendedor do produto"],
    },
    stock: {
      type: Number,
      required: [true, "Por favor, insira o estoque do produto"],
    },
    numOfReviews: {
      type: Number,
      default: 0,
    },
    reviews: [
      {
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true,
        },
        rating: {
          type: Number,
          required: true,
        },
        comment: {
          type: String,
          required: true,
        },
      },
    ],
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model("Product", productSchema);
