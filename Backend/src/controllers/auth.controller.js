import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";

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
