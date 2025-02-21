import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import { Lucia } from "lucia";
import { cookies } from "next/headers";
import db from "./db";

const adapter = new BetterSqlite3Adapter(db, {
  user: "users",
  session: "sessions",
});

const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
});

export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session?.id);
  const { name, value, attributes } = sessionCookie;
  cookies().set(name, value, attributes);
}

export async function verifyAuthSession() {
  const sessionCookie = cookies().get(lucia.sessionCookieName);
  if (!sessionCookie) {
    return {
      user: null,
      session: null,
    };
  }
  const sessionId = sessionCookie.value;
  if (!sessionId) {
    return {
      user: null,
      session: null,
    };
  }
  const result = await lucia.validateSession(sessionId);
  try {
    if (result.session && result.session.fresh) {
      const refreshedSessionCookie = lucia.createSessionCookie(
        result.session.id
      );
      cookies().set(
        refreshedSessionCookie.name,
        refreshedSessionCookie.value,
        refreshedSessionCookie.attributes
      );
    }

    if (!result.session) {
      const sessionCookieForInvalidSession = lucia.createBlankSessionCookie();
      cookies().set(
        sessionCookieForInvalidSession.name,
        sessionCookieForInvalidSession.value,
        sessionCookieForInvalidSession.attributes
      );
    }
  } catch (e) {}

  return result;
}

export async function destroySession() {
  const { session } = await verifyAuthSession();
  if (!session) {
    return {
      error: "Unauthorized!!!",
    };
  }

  await lucia.invalidateSession(session.id);
  const sessionCookieForInvalidSession = lucia.createBlankSessionCookie();
  cookies().set(
    sessionCookieForInvalidSession.name,
    sessionCookieForInvalidSession.value,
    sessionCookieForInvalidSession.attributes
  );
}
