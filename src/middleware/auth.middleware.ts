import { Request, Response, NextFunction } from "express";
import { AuthUtils } from "../utils";
import { IUserDoc, IUserModel } from "../types";

export interface AuthRequest extends Request {
  user?: IUserDoc;
}

export class AuthMiddleware {
  private authUtils: AuthUtils;
  private userModel: IUserModel;

  constructor(authUtils: AuthUtils, userModel: IUserModel) {
    this.authUtils = authUtils;
    this.userModel = userModel;
  }

  private async parseUserFromRequestToken(
    req: Request,
  ): Promise<IUserDoc | null> {
    const authHeader = req.headers.authorization;
    const token = AuthUtils.extractTokenFromHeader(authHeader || "");
    if (!token) return null;
    try {
      const decoded = this.authUtils.verifyToken(token);
      const user = await this.userModel.findById(decoded.userId);
      if (user && user.isActive) {
        return user;
      }
      return null;
    } catch {
      return null;
    }
  }

  // JWT Authentication middleware
  authenticate = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      if (!!req.user) {
        return next();
      }
      const user = await this.parseUserFromRequestToken(req);
      if (!user) {
        res.status(401).json({ error: "Access token required or invalid" });
        return;
      }
      req.user = user;
      next();
    } catch {
      res.status(401).json({ error: "Invalid or expired token" });
    }
  };

  // Optional authentication middleware (doesn't fail if no token)
  parseAuthTokenSoftly = async (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      if (!!req.user) {
        return next();
      }
      const user = await this.parseUserFromRequestToken(req);
      if (user) {
        req.user = user;
      }
      next();
    } catch {
      // Continue without authentication
      next();
    }
  };

  // Role-based authorization middleware
  authorizeRole = (roles: string[]) => {
    return async (
      req: AuthRequest,
      res: Response,
      next: NextFunction,
    ): Promise<void> => {
      if (!req.user) {
        const user = await this.parseUserFromRequestToken(req);
        if (!user) {
          res.status(401).json({ error: "Authentication required" });
          return;
        }
        req.user = user;
      }
      const hasPermission = roles.some((role) => req.user?.role === role);
      if (!hasPermission) {
        res.status(403).json({ error: "Insufficient permissions" });
        return;
      }
      next();
    };
  };

  requireVerifiedEmail = (
    req: AuthRequest,
    res: Response,
    next: NextFunction,
  ): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }

    if (!req.user.isEmailVerified) {
      res.status(403).json({ error: "Email verification required" });
      return;
    }

    next();
  };
}

export const createAuthMiddleware = (
  authUtils: AuthUtils,
  userModel: IUserModel,
): AuthMiddleware => {
  return new AuthMiddleware(authUtils, userModel);
};
