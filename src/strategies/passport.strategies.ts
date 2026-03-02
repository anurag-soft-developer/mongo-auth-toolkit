import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { IUserModel } from "../types";

export class AuthStrategies {
  private userModel: IUserModel;

  constructor(userModel: IUserModel) {
    this.userModel = userModel;
  }

  // Configure Local Strategy for email/password authentication
  configureLocalStrategy(): void {
    passport.use(
      new LocalStrategy(
        {
          usernameField: "email",
          passwordField: "password",
        },
        async (email: string, password: string, done) => {
          try {
            const user = await this.userModel.findByEmail(email);

            if (!user) {
              return done(null, false, {
                message: "Invalid email or password",
              });
            }

            if (!user.isActive) {
              return done(null, false, { message: "Account is deactivated" });
            }

            const isValidPassword = await user.comparePassword(password);

            if (!isValidPassword) {
              return done(null, false, {
                message: "Invalid email or password",
              });
            }

            // Update last login
            user.lastLogin = new Date();
            await user.save();

            return done(null, user);
          } catch (error) {
            return done(error);
          }
        },
      ),
    );
  }

  // Configure Google OAuth Strategy
  configureGoogleStrategy(config: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  }): void {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.clientId,
          clientSecret: config.clientSecret,
          callbackURL: config.callbackURL,
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            let user = await this.userModel.findByOAuthId("google", profile.id);

            if (user) {
              // Update last login and tokens
              const oAuthStrategy = user.oAuthStrategies.find(
                (s) => s.provider === "google" && s.id === profile.id,
              );
              if (oAuthStrategy) {
                oAuthStrategy.accessToken = accessToken;
                oAuthStrategy.refreshToken = refreshToken;
              }
              user.lastLogin = new Date();
              await user.save();
              return done(null, user);
            }

            const email = profile.emails?.[0]?.value;
            if (email) {
              user = await this.userModel.findByEmail(email);
              if (user) {
                // Link Google account to existing user
                user.oAuthStrategies.push({
                  provider: "google",
                  id: profile.id,
                  accessToken: accessToken,
                  refreshToken: refreshToken,
                  createdAt: new Date(),
                });
                user.lastLogin = new Date();
                if (!user.avatar && profile.photos?.[0]?.value) {
                  user.avatar = profile.photos[0].value;
                }
                await user.save();
                return done(null, user);
              }
            }

            user = await this.userModel.createWithOAuth("google", profile, {
              accessToken,
              refreshToken,
            });
            user.lastLogin = new Date();
            await user.save();

            return done(null, user);
          } catch (error) {
            return done(error);
          }
        },
      ),
    );
  }

  // Configure Passport serialization
  configureSerialization(): void {
    passport.serializeUser((user: any, done) => {
      done(null, user._id);
    });

    passport.deserializeUser(async (id: string, done) => {
      try {
        const user = await this.userModel.findById(id);
        done(null, user);
      } catch (error) {
        done(error);
      }
    });
  }

  // Initialize all strategies
  initialize(googleConfig?: {
    clientId: string;
    clientSecret: string;
    callbackURL: string;
  }): void {
    this.configureLocalStrategy();
    this.configureSerialization();

    if (googleConfig) {
      this.configureGoogleStrategy(googleConfig);
    }
  }
}
