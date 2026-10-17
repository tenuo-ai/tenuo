process.env.TENUO_ALLOW_DEV ??= "1";

import request from "supertest";
import { createApp } from "./app.ts";

const { app, executed } = createApp();
for (const path of ["/workspace/reports/q3.txt", "/workspace/finance/payroll.txt"]) {
  const response = await request(app).get("/reports/read").query({ path });
  console.log(response.status, path, response.body);
}
console.log("Underlying operations executed:", executed);
