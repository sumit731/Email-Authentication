import express from 'express';
import { isAuthenticated, login, logout, register, resetPassword, sendVerifyOtp, verifyEmail } from '../controllers/auth.controller.js';
import userMiddleware from '../middleware/auth.middleware.js';

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp',userMiddleware , sendVerifyOtp);
authRouter.post('/verify-account', userMiddleware, verifyEmail);
authRouter.post('/is-auth', userMiddleware, isAuthenticated);
authRouter.post('/send-reset-otp', sendVerifyOtp);
authRouter.post('/reset-password', resetPassword);

export default authRouter;