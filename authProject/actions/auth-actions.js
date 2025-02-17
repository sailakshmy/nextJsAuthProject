"use server";

import { hashUserPassword } from "@/lib/hash";
import { createUser } from "@/lib/user";
import { redirect } from "next/navigation";
import { createAuthSession } from "../lib/auth";

export async function signup(prevState, formData) {
  const email = formData.get("email");
  const password = formData.get("password");
  console.log("Here");

  let errors = {};

  if (!email.includes("@")) {
    errors.email = "Please enter a valid email address";
  }

  if (password.trim().length < 8) {
    errors.password = "Password must be at least 8 characters in length";
  }

  if (Object.keys(errors).length > 0) {
    return {
      errors,
    };
  }
  const hashedPassword = hashUserPassword(password);
  try {
    const userId = createUser(email, hashedPassword);
    await createAuthSession(userId);
    redirect("/training");
  } catch (e) {
    if (e.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return {
        errors: {
          email: "It seems like an account for the chosen email already exists",
        },
      };
    }
    throw e;
  }
}
