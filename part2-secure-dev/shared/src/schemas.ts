import { z } from "zod";

export const Severity = z.enum(["HIGH", "MEDIUM", "LOW"]);
export type Severity = z.infer<typeof Severity>;

export const Role = z.enum(["admin", "user"]);
export type Role = z.infer<typeof Role>;

export const UserStatus = z.enum(["active", "disabled"]);
export type UserStatus = z.infer<typeof UserStatus>;

/**
 * Public user shape — what the API returns. Never includes the password hash.
 */
export const UserSchema = z
  .object({
    id: z.string().uuid(),
    email: z.string().email(),
    role: Role,
    status: UserStatus,
  })
  .strict();
export type User = z.infer<typeof UserSchema>;

/**
 * Create-user input (admin-only endpoint).
 * Mass-assignment defense: only these fields are accepted; anything else (e.g., `id`, `status`) is rejected.
 */
export const CreateUserSchema = z
  .object({
    email: z.string().email(),
    password: z.string().min(12).max(128),
    role: Role.default("user"),
  })
  .strict();
export type CreateUser = z.infer<typeof CreateUserSchema>;

/**
 * Update-user input (admin-only endpoint).
 * Only role and status are settable here — email and password are intentionally NOT updatable through this route.
 */
export const UpdateUserSchema = z
  .object({
    role: Role.optional(),
    status: UserStatus.optional(),
  })
  .strict()
  .refine((data) => data.role !== undefined || data.status !== undefined, {
    message: "At least one of `role` or `status` must be provided",
  });
export type UpdateUser = z.infer<typeof UpdateUserSchema>;

export const LoginSchema = z
  .object({
    email: z.string().email(),
    password: z.string().min(1).max(128),
  })
  .strict();
export type Login = z.infer<typeof LoginSchema>;

export const LoginResponseSchema = z.object({
  user: UserSchema,
});
export type LoginResponse = z.infer<typeof LoginResponseSchema>;

export const SecurityEventSchema = z.object({
  id: z.string(),
  timestamp: z.string().datetime(),
  severity: Severity,
  title: z.string(),
  description: z.string(),
  assetHostname: z.string(),
  assetIp: z.string(),
  sourceIp: z.string(),
  tags: z.array(z.string()),
  userId: z.string(),
});
export type SecurityEvent = z.infer<typeof SecurityEventSchema>;

export const ErrorResponseSchema = z.object({
  error: z.string(),
});
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
