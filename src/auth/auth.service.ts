import passport from "passport";
import {
  AuthConfig,
  IUserDoc,
  IUserModel,
  EmailPasswordData,
  LoginCredentials,
  AuthResponse,
  UserHooks,
} from "../types";
import { createUserModel } from "../models";
import { AuthStrategies } from "../strategies";
import {
  AuthUtils,
  validateEmail,
  validatePassword,
  sanitizeUser,
} from "../utils";
import { AuthMiddleware, createAuthMiddleware } from "../middleware";

export class AuthService {
  config: AuthConfig;
  userModel: IUserModel;
  authUtils: AuthUtils;
  authStrategies: AuthStrategies;
  authMiddleware: AuthMiddleware;
  hooks: UserHooks;

  constructor(config: AuthConfig) {
    this.config = config;
    this.hooks = config.hooks || {};

    this.authUtils = new AuthUtils(config.jwt.secret, config.jwt.expiresIn);

    this.userModel = createUserModel(config.userModel, {
      mongooseConnection: config?.mongooseConnection,
    });

    this.authStrategies = new AuthStrategies(this.userModel);
    this.authStrategies.initialize(config.google);

    this.authMiddleware = createAuthMiddleware(this.authUtils, this.userModel);
  }

  // Register with email and password
  async register(userData: EmailPasswordData): Promise<AuthResponse> {
    try {
      // Validate email
      if (!validateEmail(userData.email)) {
        throw new Error("Invalid email format");
      }

      // Validate password
      const passwordValidation = validatePassword(userData.password);
      if (!passwordValidation.isValid) {
        throw new Error(
          `Password validation failed: ${passwordValidation.errors.join(", ")}`,
        );
      }

      // Check if user already exists
      const existingUser = await this.userModel.findByEmail(userData.email);
      if (existingUser) {
        throw new Error("User already exists with this email");
      }

      // Apply before create hook
      let processedData = userData;
      if (this.hooks.beforeCreate) {
        processedData = await this.hooks.beforeCreate(userData);
      }

      // Create user
      const user = await this.userModel.createWithEmailPassword(processedData);

      // Apply after create hook
      if (this.hooks.afterCreate) {
        await this.hooks.afterCreate(user);
      }

      // Generate token
      const token = this.authUtils.generateToken({
        userId: user._id.toString(),
        email: user.email,
      });

      return {
        user: sanitizeUser(user.toObject()),
        token,
      };
    } catch (error) {
      throw error;
    }
  }

  // Login with email and password
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      // Validate email
      if (!validateEmail(credentials.email)) {
        throw new Error("Invalid email format");
      }

      // Find user
      const user = await this.userModel.findByEmail(credentials.email);
      if (!user) {
        throw new Error("Invalid email or password");
      }

      if (!user.isActive) {
        throw new Error("Account is deactivated");
      }

      // Verify password
      const isValidPassword = await user.comparePassword(credentials.password);
      if (!isValidPassword) {
        throw new Error("Invalid email or password");
      }

      // Apply before login hook
      if (this.hooks.beforeLogin) {
        await this.hooks.beforeLogin(user);
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      // Apply after login hook
      if (this.hooks.afterLogin) {
        await this.hooks.afterLogin(user);
      }

      // Generate token
      const token = this.authUtils.generateToken({
        userId: user._id.toString(),
        email: user.email,
      });

      return {
        user: sanitizeUser(user.toObject()),
        token,
      };
    } catch (error) {
      throw error;
    }
  }

  // Get user by ID
  async getUserById(userId: string): Promise<IUserDoc | null> {
    try {
      return await this.userModel.findById(userId);
    } catch (error) {
      throw error;
    }
  }

  // Update user
  async updateUser(
    userId: string,
    updateData: Partial<IUserDoc>,
  ): Promise<IUserDoc | null> {
    try {
      // Apply before update hook
      let processedData = updateData;
      if (this.hooks.beforeUpdate) {
        processedData = await this.hooks.beforeUpdate(userId, updateData);
      }

      const user = await this.userModel.findByIdAndUpdate(
        userId,
        processedData,
        { new: true },
      );

      if (user && this.hooks.afterUpdate) {
        await this.hooks.afterUpdate(user, processedData);
      }

      return user;
    } catch (error) {
      throw error;
    }
  }

  async deleteUser(userId: string): Promise<boolean> {
    try {
      // Apply before delete hook
      if (this.hooks.beforeDelete) {
        await this.hooks.beforeDelete(userId);
      }

      const deleted = await this.userModel.findByIdAndDelete(userId);

      if (deleted && this.hooks.afterDelete) {
        await this.hooks.afterDelete(userId, deleted);
      }

      return !!deleted;
    } catch (error) {
      throw error;
    }
  }

  getPassport(): typeof passport {
    return passport;
  }
}
