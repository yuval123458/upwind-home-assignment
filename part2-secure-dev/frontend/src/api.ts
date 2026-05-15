import type { SecurityEvent, User } from "./types";

const API_URL = "http://localhost:3001";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const hasBody = init?.body !== undefined && init?.body !== null;
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...(hasBody ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });
  const ct = res.headers.get("content-type") ?? "";
  const body = ct.includes("application/json") ? await res.json() : null;
  if (!res.ok) {
    const message = body && typeof body.error === "string" ? body.error : res.statusText;
    throw new ApiError(res.status, message);
  }
  return body as T;
}

// ---------- Auth ----------

export function login(email: string, password: string): Promise<{ user: User }> {
  return request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export function logout(): Promise<{ message: string }> {
  return request("/api/auth/logout", { method: "POST" });
}

export function getMe(): Promise<User> {
  return request("/api/auth/me");
}

// ---------- Events ----------

export interface EventsPage {
  items: SecurityEvent[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export function getEvents(page = 1, limit = 25): Promise<EventsPage> {
  return request(`/api/events?page=${page}&limit=${limit}`);
}

export function getEvent(id: string): Promise<SecurityEvent> {
  return request(`/api/events/${encodeURIComponent(id)}`);
}

// ---------- Users (admin only) ----------

export function getUsers(): Promise<User[]> {
  return request("/api/users");
}

export function createUser(input: {
  email: string;
  password: string;
  role: "admin" | "user";
}): Promise<User> {
  return request("/api/users", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateUser(
  id: string,
  fields: { role?: "admin" | "user"; status?: "active" | "disabled" }
): Promise<User> {
  return request(`/api/users/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(fields),
  });
}

export function deleteUser(id: string): Promise<{ message: string }> {
  return request(`/api/users/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}
