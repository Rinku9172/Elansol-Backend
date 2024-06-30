require('dotenv').config();

const mongoose = require('mongoose');
const mongoURI = process.env.REACT_APP_MONGO_CONNECT
const connectToMongo = async ()=>{
    await mongoose.connect(mongoURI,{
        serverSelectionTimeoutMS: 5000, 
        connectTimeoutMS: 10000, 
        socketTimeoutMS: 45000,
    } ,()=>{
        console.log("Connected to Mongo Successfully");
    })
}

module.exports = connectToMongo;

