import express from 'express';
import { isAuthenticated, login, logout, register, sendVerifyOtp, verifyEmail } from '../controllers/auth.controller.js';
import userMiddleware from '../middleware/user.middleware.js';

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp',userMiddleware , sendVerifyOtp);
authRouter.post('/verify-account', userMiddleware, verifyEmail);
authRouter.post('/is-auth', userMiddleware, isAuthenticated);

export default authRouter;