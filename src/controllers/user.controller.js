import { asyncHandler } from "../utlis/asynchandler.js";
import { ApiError } from "../utlis/apierror.js";
import { ApiResponse } from "../utlis/apiresponse.js";
import {User} from "../models/user.models.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const generateAccessTokenAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    console.error("Error in generating token: ", error);
    throw new ApiError(500, "Error in generating token");
  }
};

// Function to register a new user
const signupUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  // Check if all fields are filled
  if ([email, username, password].some((value) => !value?.trim())) {
    throw new ApiError(400, "All fields are required");
  }

  // Validate email format
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    throw new ApiError(400, "Enter a valid email");
  }

  // Check if user already exists
  const existedUser = await User.findOne({ $or: [{ email }, { username }] });
  if (existedUser) {
    throw new ApiError(409, "Email or username already exists");
  }

  // Create new user
  const newUser = await User.create({
    email,
    username,
    password,
  });

  const createdUser = await User.findById(newUser._id).select("-password -refreshToken");
  if (!createdUser) {
    throw new ApiError(500, "User not created");
  }

  const { accessToken, refreshToken } = await generateAccessTokenAndRefreshToken(createdUser._id);

  return res.status(201).json(
    new ApiResponse(
      201,
      { user: createdUser, accessToken, refreshToken },
      "User created successfully"
    )
  );
});

const verifyPassword = async (inputPassword, storedPasswordHash) => {
  return await bcrypt.compare(inputPassword, storedPasswordHash);
};

// Function to log in a user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Check if email and password are provided
  if (!email || !password) {
    throw new ApiError(400, "Email and password are required");
  }

  // Find user by email
  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // Validate password
  const isPasswordValid = await verifyPassword(password, user.password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid password");
  }

  const { accessToken, refreshToken } = await generateAccessTokenAndRefreshToken(user._id);
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

  return res.status(200).json(
    new ApiResponse(
      200,
      { user: loggedInUser, accessToken, refreshToken },
      "User logged in successfully"
    )
  );
});

// Function to log out a user
const logoutUser = asyncHandler(async (req, res) => {
  // In a React Native app, the refresh token is sent in the request body or header
  const refreshToken = req.body?.refreshToken || req.headers["x-refresh-token"];

  if (!refreshToken) {
    throw new ApiError(400, "No refresh token provided");
  }

  const user = await User.findOne({ refreshToken });
  if (!user) {
    throw new ApiError(400, "Invalid refresh token");
  }

  // Remove refresh token from user
  user.refreshToken = null;
  await user.save({ validateBeforeSave: false });

  return res.status(200).json(new ApiResponse(200, {}, "User logged out successfully"));
});

// Function to refresh access token
const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken = req.body?.refreshToken || req.headers["x-refresh-token"];

  if (!incomingRefreshToken) {
    throw new ApiError(400, "No refresh token provided");
  }

  const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
  const user = await User.findById(decodedToken?._id).select("-password -refreshToken");

  if (!user) {
    throw new ApiError(401, "Invalid refresh token");
  }

  if (user.refreshToken !== incomingRefreshToken) {
    throw new ApiError(401, "Invalid or used refresh token");
  }

  const { accessToken, refreshToken } = await generateAccessTokenAndRefreshToken(user._id);

  return res.status(200).json(
    new ApiResponse(
      200,
      { accessToken, refreshToken, user },
      "Access token refreshed successfully"
    )
  );
});

export { signupUser, loginUser, logoutUser, refreshAccessToken };