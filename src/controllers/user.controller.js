import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId)
    const accessToken = user.generateAccessToken()
    const refreshToken = user.generateRefreshToken()

    user.refreshToken = refreshToken
    await user.save({ validateBeforeSave: false })

    return { accessToken, refreshToken }
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating access & refresh token"
    )
  }
}

const registerUser = asyncHandler(async (req, res) => {
  //   res.status(200).json({
  //     message: "ok",
  //   })

  const { fullName, email, username, password } = req.body

  if (
    [fullName, email, username, password].some(
      (field) => field?.trim() === "" || !field
    )
  ) {
    throw new ApiError(400, "All fields are required")
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  })

  if (existedUser)
    throw new ApiError(409, "User already exist with username or email")

  const avatarLocalPath = req.files?.avatar[0]?.path
  let coverImageLocalPath
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files?.coverImage[0]?.path
  }

  if (!avatarLocalPath) throw new ApiError(400, "Avatar file is required")

  const avatar = await uploadOnCloudinary(avatarLocalPath)
  const coverImage = await uploadOnCloudinary(coverImageLocalPath)

  if (!avatar) throw new ApiError(400, "Avatar upload failed")

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  })

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  )

  if (!createdUser) throw ApiError(500, "Error while registering user")

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registerd Successfully !!"))
})

const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body
  if (!username && !email)
    throw new ApiError(400, "username or email is required")

  const user = await User.findOne({
    $or: [{ username }, { email }],
  })

  if (!user) throw new ApiError(404, "User does not exist")

  const isCorrectPassword = await user.isPasswordCorrect(password)
  if (!isCorrectPassword) throw new ApiError(401, "Incorrect credentials")

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  )

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  )
  const options = {
    httpOnly: true,
    secure: true,
  }
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User logged in successfully !!!"
      )
    )
})

const logoutUser = asyncHandler(async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  )

  const options = {
    httpOnly: true,
    secure: true,
  }
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, "User logged out successfully !!!"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
  const inputRefreshToken = req.cookies?.refreshToken || req.body.refreshToken
  if (!inputRefreshToken)
    throw new ApiError(401, "Unauthorized: refresh token not found")

  try {
    const decodedToken = jwt.verify(
      inputRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    )
    const user = await User.findById(decodedToken._id)

    if (!user) throw new ApiError(401, "Unauthorized: invalid refresh token")

    if (inputRefreshToken !== user.refreshToken)
      throw new ApiError(401, "Unauthorized: refresh token expired")

    const options = {
      httpOnly: true,
      secure: true,
    }
    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id)

    return res
      .status(200)
      .cookies("accessToken", accessToken, options)
      .cookies("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, newRefreshToken },
          "Access token refreshed"
        )
      )
  } catch (error) {
    throw new ApiError(401, error?.message || "Unauthorized request")
  }
})

const updateUserPassword = asyncHandler(async (req, res) => {
  const { password, newPassword } = req.body
  if (!password || !newPassword) throw new ApiError(400, "Password not found")

  const user = User.findById(req.user?._id)
  const isCorrectPassword = user.isPasswordCorrect(password)
  if (!isCorrectPassword) throw new ApiError(400, "Incorrect old user password")

  user.password = newPassword
  await user.save({ validateBeforeSave: false })

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "password changed successfully !!!"))
})

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user fetched"))
})

const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body
  if (!fullName || !email)
    throw new ApiError(400, " Fullname and email are required")

  const user = User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName,
        email,
      },
    },
    { new: true }
  ).select("-password")

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated"))
})

const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path
  if (!avatarLocalPath) throw new ApiError(400, "Avatar file not found")

  const avatar = await uploadOnCloudinary(avatarLocalPath)
  if (!avatar)
    throw new ApiError(500, "Error while uploading avatar to cloudinary")

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        avatar: avatar.url,
      },
    },
    { new: true }
  ).select("-password")

  return res.status(200).json(new ApiResponse(200, user, "User avatar updated"))
})

const updateUserCoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path
  if (!coverImageLocalPath)
    throw new ApiError(400, "Cover image file not found")

  const coverImage = await uploadOnCloudinary(coverImageLocalPath)
  if (!coverImage)
    throw new ApiError(500, "Error while uploading cover image to cloudinary")

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        coverImage: coverImage.url,
      },
    },
    { new: true }
  ).select("-password")

  return res
    .status(200)
    .json(new ApiResponse(200, user, "User cover image updated"))
})

const getUserChannelProfile = asyncHandler(async (req, res) => {
  const { username } = req.params
  if (!username?.trim()) throw new ApiError(400, "username not found")

  const channel = await User.aggregate([
    {
      $match: {
        username: username.toLowerCase(),
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo",
      },
    },
    {
      $addFields: {
        subscribersCount: {
          $size: "$subscribers",
        },
        subscribedToCount: {
          $size: "$subscribedTo",
        },
        isSubscribed: {
          $cond: {
            if: { $in: [req.user?._id, "$subscribers.subscriber"] },
            then: true,
            else: false,
          },
        },
      },
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        isSubscribed: 1,
        subscribersCount: 1,
        subscribedToCount: 1,
        avatar: 1,
        coverImage: 1,
        email: 1,
      },
    },
  ])

  if (!channel?.length) throw new ApiError(400, "Channel not found")

  return res
    .status(200)
    .json(new ApiResponse(200, channel[0], "User channel details fetched"))
})

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  updateUserPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
}
