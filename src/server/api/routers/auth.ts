import { z } from "zod";

import { createTRPCRouter, publicProcedure } from "@/server/api/trpc";
import bcrypt from "bcrypt";
import crypto from "crypto";

export const authRouter = createTRPCRouter({
  signup: publicProcedure
    .input(
      z.object({
        email: z.string().email("Must be an email"),
        password: z.string().min(8, "Must be at least 8 characters"),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const { email, password } = input;
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(password, salt);

      return ctx.prisma.account.create({
        data: {
          email: email,
          password_hash: hash,
          salt: salt,
        },
      });
    }),
  login: publicProcedure
    .input(
      z.object({
        email: z.string().email("Must be an email"),
        password: z.string().min(8, "Must be at least 8 characters"),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const { email, password } = input;
      const account = await ctx.prisma.account.findUnique({
        where: {
          email: email,
        },
      });
      if (account) {
        const valid = await bcrypt.compare(password, account.password_hash);
        if (valid) {
          // generate session id
          // store session id in db
          // return session id

          const sessionId = crypto.randomUUID();
          const session = await ctx.prisma.sesssion.create({
            data: {
              session: sessionId,
              expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
              userId: account.id,
            },
          });
          ctx.res.setHeader("Set-Cookie", `session=${sessionId}`);
          return "success";
        }
      }
      return "fail";
    }),
});
