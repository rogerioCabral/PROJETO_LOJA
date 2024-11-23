import mongoose from "mongoose";

export const connectDatabase = () => {

    let DB_URI = process.env.DB_URI;

    mongoose.connect(DB_URI).then((con) => {
        console.log(`Conectado ao Banco de Dados MongoDb com o HOST: ${con.connection?.host}`);    
    });
};