import { Router } from "express";
import { AuthService } from "../auth";
import { AuthMiddleware } from "./auth.middleware";
import { userRegistrationSchema, userLoginSchema } from "../types";
import { ValidationUtils } from "../utils";

export function createAuthRoutes(
  authService: AuthService,
  authMiddleware: AuthMiddleware,
) {
  const router = Router();

  router.post("/register", async (req, res) => {
    try {
      const parsed = userRegistrationSchema.safeParse(req.body);
      if (!parsed.success) {
        return res
          .status(400)
          .json(ValidationUtils.formatValidationError(parsed.error));
      }
      const result = await authService.register(parsed.data);
      res.json(result);
    } catch (err) {
      console.error("Registration error:", err);
      res.status(400).json({ error: "Failed to register" });
    }
  });

  router.post("/login", async (req, res) => {
    try {
      const parsed = userLoginSchema.safeParse(req.body);
      if (!parsed.success) {
        return res
          .status(400)
          .json(ValidationUtils.formatValidationError(parsed.error));
      }
      const result = await authService.login(parsed.data);
      res.json(result);
    } catch (err) {
      console.error("Login error:", err);
      res.status(400).json({ error: "Failed to login" });
    }
  });

  router.get(
    "/google",
    authService
      .getPassport()
      .authenticate("google", { scope: ["profile", "email"] }),
  );

  router.get(
    "/google/callback",
    authService.getPassport().authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
      res.json(req.user);
    },
  );

  router.get("/me", authMiddleware.authenticate, (req, res) => {
    res.json(req.user);
  });

  return router;
}

export default createAuthRoutes;
