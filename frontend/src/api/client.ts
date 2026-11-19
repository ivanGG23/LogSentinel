import type { components } from "./schema";

export type Alert = components["schemas"]["AlertOut"];
export type AlertStatus = NonNullable<components["schemas"]["AlertUpdate"]["status"]>;

export interface Filters {
  status: string;
  severity: string;
  rule: string;
}

const API_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "No se pudo conectar con la API");
  }
  if (!res.ok) throw new ApiError(res.status, `Error ${res.status}`);
  return (await res.json()) as T;
}

export async function login(username: string, password: string): Promise<string> {
  const data = await request<{ access_token: string }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  return data.access_token;
}

export function listAlerts(token: string, filters: Filters): Promise<Alert[]> {
  const q = new URLSearchParams({ limit: "200" });
  for (const [key, value] of Object.entries(filters)) {
    if (value) q.set(key, value);
  }
  return request<Alert[]>(`/alerts?${q.toString()}`, {}, token);
}

export function updateAlert(token: string, id: number, status: AlertStatus): Promise<Alert> {
  return request<Alert>(`/alerts/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  }, token);
}
