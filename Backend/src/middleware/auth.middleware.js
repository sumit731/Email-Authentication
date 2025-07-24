import jwt from 'jsonwebtoken';

const userMiddleware = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.json({
            success: false,
            message: "Unauthorized"
        });
    }

    try {
        const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (tokenDecoded.id) {
            req.userId = tokenDecoded.id; // Attach user ID to request body
        }
        else {
            res.json({
                success: false,
                message: "Invalid token"
            });
        }

        next();
    } catch (error) {
        return res.json({
            success: false,
            message: error.message || "Token verification failed"
        });
    }
}

export default userMiddleware;