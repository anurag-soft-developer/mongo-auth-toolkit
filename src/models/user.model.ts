import mongoose, { Schema, model } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  IUserDoc,
  IUserModel,
  EmailPasswordData,
  userRegistrationSchema,
  userLoginSchema,
  userUpdateSchema,
  UserLoginData,
  UserUpdateData,
} from "../types";
import { Profile } from "passport-google-oauth20";

const defaultUserSchema = new Schema<IUserDoc>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      select: false,
    },
    role:String,
    oAuthStrategies: [
      {
        provider: {
          type: String,
          required: true,
          enum: ["google", "facebook", "github", "twitter", "linkedin"],
        },
        id: {
          type: String,
          required: true,
        },
        accessToken: String,
        refreshToken: String,
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    firstName: {
      type: String,
      trim: true,
    },
    lastName: {
      type: String,
      trim: true,
    },
    avatar: {
      type: String,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    lastLogin: {
      type: Date,
    },
  },
  {
    timestamps: true,
  },
);

// Enhanced function to create User model with additional fields
export function createUserModel(
  additionalFields?: Schema,
  options?: { modelName?: string; mongooseConnection?: mongoose.Connection },
): IUserModel {
  const { modelName = "User", mongooseConnection } = options || {};
  let schema: Schema<IUserDoc>;

  if (additionalFields && Object.keys(additionalFields.obj).length > 0) {
    schema = new Schema<IUserDoc>(
      {
        ...defaultUserSchema.obj,
        ...additionalFields.obj,
      },
      {
        timestamps: true,
      },
    );
  } else {
    schema = defaultUserSchema;
  }

  schema = assignMethods(schema);

  if (mongooseConnection) {
    return mongooseConnection.model<IUserDoc, IUserModel>(modelName, schema);
  }

  return model<IUserDoc, IUserModel>(modelName, schema);
}

function assignMethods(defaultUserSchema: Schema<IUserDoc>) {
  // Pre-save middleware to hash password
  defaultUserSchema.pre("save", async function (this) {
    if (!this.isModified("password") || !this.password) return;

    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
  });

  defaultUserSchema.methods.comparePassword = async function (
    candidatePassword: string,
  ): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
  };

  defaultUserSchema.methods.generateAuthToken = function (): string {
    const payload = {
      userId: this._id.toString(),
      email: this.email,
    };

    const secret = process.env.JWT_SECRET || "default-secret";
    return jwt.sign(payload, secret, { expiresIn: "24h" });
  };

  defaultUserSchema.statics.findByEmail = function (email: string) {
    return this.findOne({ email }).select("+password");
  };

  defaultUserSchema.statics.findByOAuthId = function (
    provider: string,
    oAuthId: string,
  ) {
    return this.findOne({
      "oAuthStrategies.provider": provider,
      "oAuthStrategies.id": oAuthId,
    });
  };

  // Static method to create user with OAuth profile
  defaultUserSchema.statics.createWithOAuth = async function (
    provider: string,
    profile: Profile,
    tokens?: { accessToken?: string; refreshToken?: string },
  ) {
    const userData = {
      email: profile.emails?.[0]?.value,
      oAuthStrategies: [
        {
          provider,
          id: profile.id,
          accessToken: tokens?.accessToken,
          refreshToken: tokens?.refreshToken,
        },
      ],
      firstName: profile.name?.givenName,
      lastName: profile.name?.familyName,
      avatar: profile.photos?.[0]?.value,
      isEmailVerified: profile.emails?.[0]?.verified || false,
    };

    return this.create(userData);
  };

  defaultUserSchema.statics.createWithEmailPassword = async function (
    data: EmailPasswordData,
  ) {
    const validatedData = userRegistrationSchema.parse(data);
    return this.create(validatedData);
  };

  // Static method to validate login credentials
  defaultUserSchema.statics.validateLoginCredentials = function (
    data: any,
  ): UserLoginData {
    return userLoginSchema.parse(data);
  };

  // Static method to validate user update data
  defaultUserSchema.statics.validateUpdateData = function (
    data: any,
  ): UserUpdateData {
    return userUpdateSchema.parse(data);
  };

  return defaultUserSchema;
}
