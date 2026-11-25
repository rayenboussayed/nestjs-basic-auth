import { z } from "zod"

export const EnvironmentSchema = z.object({
    AUTH_NAME: z.string().trim().min(1).optional(),
    AUTH_PASS: z.string().trim().min(1).optional(),
    AUTH_REALM: z.string().trim().min(1).optional(),
})

export const environment = EnvironmentSchema.parse(process.env)