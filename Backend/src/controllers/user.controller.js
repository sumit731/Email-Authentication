import User from "../models/user.model.js";

export const getUserData = async(req, res) => {
    try{
        const {userId} = req.userId ? req : req.body;

        const user = await User.findById(userId);

        if(!user){
            return res.json({
                success: false,
                message: "User not found"
            });
        }

        res.json({
            success: true,
            data: user
        })
    }
    catch(error){
        console.error("Error in getUserData:", error);
        return res.json({
            success: false,
            message: error.message || "Internal server error"
        });
    }
}