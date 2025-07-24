import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import 'dotenv/config';
import connectDB from "./src/utils/db.js";
import authRouter from "./src/routes/auth.route.js";

const app = express();
const PORT = process.env.PORT || 5000;
//Database connection
connectDB();

//middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));

//routes
app.use('/api/auth', authRouter);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});