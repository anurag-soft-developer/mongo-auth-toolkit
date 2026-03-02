import mongoose, { Document, Model, Schema, Types } from "mongoose";
import { Profile } from "passport-google-oauth20";
import { z } from "zod";

export const emailSchema = z
  .string()
  .email("Invalid email format")
  .toLowerCase();
export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128, "Password too long");
export const nameSchema = z
  .string()
  .trim()
  .min(1, "Name cannot be empty")
  .max(50, "Name too long")
  .optional();

export const userRegistrationSchema = z
  .object({
    email: emailSchema,
    password: passwordSchema,
    firstName: nameSchema,
    lastName: nameSchema,
  })
  .strict();

export const userLoginSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(1, "Password is required"),
  })
  .strict();

export const userUpdateSchema = z
  .object({
    firstName: nameSchema,
    lastName: nameSchema,
    avatar: z.string().url("Invalid avatar URL").optional(),
    isActive: z.boolean().optional(),
  })
  .strict()
  .partial();

export type UserRegistrationData = z.infer<typeof userRegistrationSchema>;
export type UserLoginData = z.infer<typeof userLoginSchema>;
export type UserUpdateData = z.infer<typeof userUpdateSchema>;

export interface IOAuthStrategy {
  provider: "google" | "facebook" | "github" | "twitter" | "linkedin";
  id: string;
  accessToken?: string;
  refreshToken?: string;
  createdAt: Date;
}

export interface IUser {
  _id: string;
  email: string;
  password?: string;
  role?: string;
  oAuthStrategies: IOAuthStrategy[];
  firstName?: string;
  lastName?: string;
  avatar?: string;
  isActive: boolean;
  isVerified: boolean;
  isEmailVerified: boolean;
  lastLogin?: string;
  createdAt: string;
  updatedAt: string;
}

export interface IUserDoc extends Document, Omit<IUser, "_id"|'lastLogin'|'createdAt'|'updatedAt'> {
  _id: Types.ObjectId;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
  // Instance methods
  comparePassword(candidatePassword: string): Promise<boolean>;
  generateAuthToken(): string;
}

// Extensible User Model Interface
export interface IUserModel<T extends IUserDoc = IUserDoc> extends Model<T> {
  findByEmail(email: string): Promise<T | null>;
  findByOAuthId(provider: string, oAuthId: string): Promise<T | null>;
  createWithOAuth(
    provider: string,
    profile: Profile,
    tokens?: { accessToken?: string; refreshToken?: string },
  ): Promise<T>;
  createWithEmailPassword(data: EmailPasswordData): Promise<T>;

  // Zod validation methods
  validateLoginCredentials(data: any): UserLoginData;
  validateUpdateData(data: any): UserUpdateData;
}

// Authentication Configuration
export interface AuthConfig {
  jwt: {
    secret: string;
    expiresIn?: string;
  };
  google?: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  };
  mongooseConnection?: mongoose.Connection;
  hooks?: UserHooks;
  userModel?: Schema;
  hashRounds?: number;
}

// User CRUD Hooks
export interface UserHooks {
  beforeCreate?: (userData: any) => Promise<any> | any;
  afterCreate?: (user: IUserDoc) => Promise<void> | void;
  beforeUpdate?: (userId: string, updateData: any) => Promise<any> | any;
  afterUpdate?: (user: IUserDoc, updateData: any) => Promise<void> | void;
  beforeDelete?: (userId: string) => Promise<void> | void;
  afterDelete?: (userId: string, deletedUser: IUserDoc) => Promise<void> | void;
  beforeLogin?: (user: IUserDoc) => Promise<void> | void;
  afterLogin?: (user: IUserDoc) => Promise<void> | void;
}

export type EmailPasswordData = UserRegistrationData;

// JWT Payload
export interface JWTPayload {
  userId: string;
  email: string;
  iat?: number;
  exp?: number;
}

export interface AuthResponse {
  user: Omit<IUser, "password">;
  token: string;
}

export type LoginCredentials = UserLoginData;
