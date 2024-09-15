import express, { Request, Response } from "express";
import dotenv from "dotenv";
import { json } from "body-parser";
import { getUserRepos } from "./controllers/githubController";
import crypto from "crypto";

dotenv.config();

const app = express();
const port = process.env.PORT || 8000;
console.log(process.env.PORT);

app.use(json({ limit: "100kb" }));

const verifySignature = (req: Request) => {
  const secret = process.env.GITHUB_WEBHOOK_SECRET || "";
  const signature = req.headers["x-hub-signature-256"] as string;

  if (!signature) {
    console.error("Missing signature");
    return false;
  }

  const hmac = crypto.createHmac("sha256", secret);
  const digest = `sha256=${hmac
    .update(JSON.stringify(req.body))
    .digest("hex")}`;

  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
};

app.post("/webhook", (req: Request, res: Response) => {
  if (verifySignature(req)) {
    const event = req.headers["x-github-event"];
    const payload = req.body;

    console.log(`Received github event: ${event}`);
    if (event === "push") {
      console.log("Received push event:", payload);
    }
    res.status(200).json("Webhook received");
  } else {
    res.status(403).json("Invalid signature");
  }
});

app.get("/github/:username", getUserRepos);

app.use((err: Error, req: Request, res: Response, next: Function) => {
  console.error(err.stack);
  res.status(500).json({ message: "Internal Server Error" });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
