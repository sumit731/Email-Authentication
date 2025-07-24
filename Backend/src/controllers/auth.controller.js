import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import transporter from "../utils/transporter.js";

export const register = async(req, res) => {
    const {name, email, password} = req.body;

    if(!name || !email || !password){
        return res.json({
            success: false,
            message: "All fields are required"
        });
    }

    try{
        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.json({
                success: false,
                message: "User already exists"
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({name, email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET,{expiresIn: "7d"});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        })

        // sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to Our Service",
            text: `Hello ${name},\n\nThank you for registering with us. We are excited to have you on board!\n\nBest regards,\nThe Team`
        }

        await transporter.sendMail(mailOptions);

        return res.json({
            success: true,
            message: "Registration successful"
        });
    }
    catch(error){
        console.error("Error in register:", error);
        return res.json({
            success: false,
            message: "Internal server error"
        });
    }
}

export const login = async(req, res) => {
    const {email, password} = req.body;

    if(!email || !password){
        return res.json({
            success: false,
            message: "All fields are required"
        });
    }

    try{
        const user = await User.findOne({email});

        if(!user){
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch){
            return res.json({
                success: false,
                message: "Invalid credentials"
            });
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: "7d"});

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        return res.json({
            success: true,
            message: "Login successful"
        });
    }
    catch(error){
        console.error("Error in login:", error);
        return res.json({
            success: false,
            message: "Internal server error"
        });
    }
}

export const logout = (req, res) => {
    try{
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });

        return res.json({
            success: true,
            message: "Logout successful"
        });
    }
    catch(error){
        console.error("Error in logout:", error);
        return res.json({
            success: false,
            message: "Internal server error"
        });
    }
};

//send verification OTP to user's email
export const sendVerifyOtp = async(req, res) => {
    try{
        const {userId} = req.body;
        const user = await User.findById(userId);

        if(user.isAccountVerified){
            return res.json({
                success: false,
                message: "Account already verified"
            });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000)); // generate 6 digit OTP

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // OTP valid for 24 hours
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification",
            text: `Hello ${user.name},\n\nPlease use the following OTP to verify your account: ${otp}\n\nBest regards,\nThe Team`
        }

        await transporter.sendMail(mailOptions);
        return res.json({
            success: true,
            message: "Verification OTP sent to your email"
        });
    }
    catch(error){
        return res.json({
            success: false,
            message: "Internal server error"
        });
    }
}

export const verifyEmail = async(req, res) => {
    const {userId, otp} = req.body || req.userId;

    if(!userId || !otp){
        return res.json({
            success: false,
            message: "User ID and OTP are required"
        });
    }

    try{
        const user = await User.findById(userId);

        if(!user || user.isAccountVerified){
            return res.json({
                success: false,
                message: "Invalid request"
            });
        }

        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({
                success: false,
                message: "Invalid OTP"
            });
        }
        if(Date.now() > user.verifyOtpExpireAt){
            return res.json({
                success: false,
                message: "OTP has expired"
            });
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;
        await user.save();

        return res.json({
            success: true,
            message: "Account verified successfully"
        });
    }
    catch(error){
        console.error("Error in verifyEmail:", error);
        return res.json({
            success: false,
            message: "Internal server error"
        });
    }
}

export const isAuthenticated = async(req, res) => {
    try{
        return res.json({
            success: true,
            message: "User is authenticated",
        })
    }
    catch(error){
        res.json({
            success: false,
            message: error.message
        })
    }
}

export const sendResetOtp = async(req, res) => {
    const {email} = req.body;

    if(!email){
        return res.json({
            success: false,
            message: "Email is required"
        });
    }

    try{
        const user = await User.findOne({email});

        if(!user){
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000)); // generate 6 digit OTP

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000; // OTP valid for 15 minutes
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Password Reset OTP",
            text: `Hello ${user.name},\n\nPlease use the following OTP to reset your password: ${otp}\n\nBest regards,\nThe Team`
        }

        await transporter.sendMail(mailOptions);
        
        return res.json({
            success: true,
            message: "Reset OTP sent to your email"
        });
    }
    catch(error){
        console.error("Error in sendResetOtp:", error);
        return res.json({
            success: false,
            message: error.message || "Internal server error error"
        });
    }
}

export const resetPassword = async(req, res) => {
    const {email, otp, newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({
            success: false,
            message: "Email, OTP, and new password are required"
        });
    }

    try{
        const user = await User.findOne({email});

        if(!user){
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        if(user.resetOtp === '' || user.resetOtp !== otp){
            return res.json({
                success: false,
                message: "Invalid OTP"
            });
        }
        if(Date.now() > user.resetOtpExpireAt){
            return res.json({
                success: false,
                message: "OTP has expired"
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.json({
            success: true,
            message: "Password reset successfully"
        });
    }
    catch(error){
        console.error("Error in resetPassword:", error);
        return res.json({
            success: false,
            message: error.message || "Internal server error"
        });
    }
}
