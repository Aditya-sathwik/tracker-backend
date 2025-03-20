import { Router } from "express";
import { signupUser,loginUser,logoutUser } from "../controllers/user.controller.js";
 import { Signupvalidation, loginValidation } from "../middlewares/auth.validation.js";
import { verifyJWT } from "../middlewares/jwtvalidation.middleware.js";

const router = Router();

router.route("/signup").post(Signupvalidation,signupUser);

router.route("/login").post(loginValidation,loginUser);

router.route("/logout").post (logoutUser);

// router.route("/refresh-token").post(loginuser);

//router.route("/loginuser").post(loginvalidation,loginuser);


// router.route("/register").post(
//     upload.fields([
//         {
//             name: "avatar",
//             maxCount: 1
//         },
//         {
//             name: "coverimage",
//             maxCount: 1
//         }
//     ]),
//     registeruser);

export default router;


// auth.routes.js

// import express from 'express';
// import { registerUser, loginUser } from '../controllers/authController.js';

// const router = express.Router();

// router.post('/register', registerUser);
// router.post('/login', loginUser);

// export default router;