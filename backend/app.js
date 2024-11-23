import express from "express";
const app = express();
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import { connectDatabase } from "./config/dbConnect.js";
import errorMiddleware from "./middlewares/errors.js";

// Handle Uncaught exceptions
process.on("uncaughtException", (err) => {
  console.log(`ERROR: ${err}`);
  console.log("Desligando devido a expectativa não detectada");
  process.exit(1);
});

dotenv.config({ path: "backend/config/config.env" });

// Conectando ao Mongodb
connectDatabase();

// função express que lida com json
app.use(express.json());
app.use(cookieParser());

// Importando todas as rotas
import productRoutes from "./routes/products.js";
import authRoutes from "./routes/auth.js";
import orderRoutes from "./routes/order.js";

app.use("/api/v1", productRoutes);
app.use("/api/v1", authRoutes);
app.use("/api/v1", orderRoutes);

// Utilizando o middleware de tratamento de erros
app.use(errorMiddleware);

const server = app.listen(process.env.PORT, () => {
  console.log(
    `Server started on PORT: ${process.env.PORT} in ${process.env.NODE_ENV} mode.`
  );
});

//Handle Unhandled Promise rejections
process.on("unhandledRejection", (err) => {
  console.log(`ERROR: ${err}`);
  console.log("Desligando o servidor devido à rejeição de promessa não tratada");
  server.close(() => {
    process.exit(1);
  });
});
