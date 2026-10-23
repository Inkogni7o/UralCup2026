import { Application, Orm, PgDriver } from "@backend/thingamajig";

export class User {
  id!: number;
  username!: string;
  passwordHash!: string;
  createdAt!: Date;
  isInstanceAdmin!: boolean;
}

export const app = new Application(User);

function poolSetting(name: string, fallback: number, maximum: number): number {
  const configured = Number(process.env[name]);
  return Number.isSafeInteger(configured) &&
    configured > 0 &&
    configured <= maximum
    ? configured
    : fallback;
}

export const driver = PgDriver.connect({
  connectionString:
    process.env.DATABASE_URL ??
    "postgres://postgres:postgres@localhost:5432/postgres",
  max: poolSetting("PG_POOL_MAX", 10, 100),
  connectionTimeoutMillis: poolSetting("PG_CONNECTION_TIMEOUT_MS", 5000, 60000),
});

export const orm = new Orm(app, driver);

export const executionContext = app.getExecutionContextManager();

export const GUEST: User = Object.assign(new User(), {
  id: 0,
  username: "",
  password_hash: "",
  created_at: new Date(0),
  is_instance_admin: false,
});

export function sudo<TResult>(callback: () => TResult): TResult {
  return executionContext.sudo(callback);
}
