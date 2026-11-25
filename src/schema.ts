import z from "zod";

export const BasicAuthBodySchema = z.object({
  auth: z
    .object({
      name: z.string().trim().min(1),
      pass: z.string().trim().min(1),
    }),
});
