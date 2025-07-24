import express from "express";
import userMiddleware from "../middleware/auth.middleware.js";
import { getUserData } from "../controllers/user.controller.js";


const userRouter = express.Router();

userRouter.get("/data", userMiddleware, getUserData);

export default userRouter;