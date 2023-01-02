const userDataBase = require('../models/userModel');
const jwt = require('jsonwebtoken');


exports.isAuthUser = async(req,res,next)=>{
    try {
        const {token} = req.cookies;
        if(token) {
            const verifyToken = jwt.verify(token,process.env.JWT_SECRET);
            req.user = await userDataBase.findById(verifyToken.id);
            next();
        }else{
            res.status(400).json({success:false,error:"please login to access this route"});
        }
    } catch (error) {
        res.status(400).json({success:false,error:error.message});
    }
}

exports.isAdmin = async(req,res,next)=>{
    try {
        const {user} = req;
       if(user){
        if(user.role=='admin') {
            next();
        }else{
            res.status(403).json({success:false,message:"you are not admin"});
        }
       }else{
        res.status(401).json({success:false,error:'plz login first'})
       }
    } catch (error) {
        res.status(401).json({success:false,error:error.message})
    }
}