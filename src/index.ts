import express, { Request, Response } from "express";
import dotenv from "dotenv";
import { json } from "body-parser";
import { getUserRepos } from "./controllers/githubController";
import crypto from "crypto";

dotenv.config();

const app = express();
const port = process.env.PORT || 8000;
console.log(process.env.PORT);

app.use((req: Request, res: Response, next) => {
    console.log(req.url);
  next();
});
app.use(
  express.json({
    verify: (req: any, res, buf, encoding) => {
      req.rawBody = buf;
    },
  })
);
const verifySignature = (req: Request & { rawBody?: Buffer }) => {
  const secret = process.env.GITHUB_WEBHOOK_SECRET || "";
  const signature256 = req.headers["x-hub-signature-256"] as string;

  if (!signature256) {
    console.error("Missing X-Hub-Signature-256 header");
    return false;
  }

  if (!req.rawBody) {
    console.error("Missing rawBody in request");
    return false;
  }

  const hmac = crypto.createHmac("sha256", secret);
  const digest = `sha256=${hmac.update(req.rawBody).digest("hex")}`;

  const isValid = crypto.timingSafeEqual(
    Buffer.from(signature256),
    Buffer.from(digest)
  );

  if (!isValid) {
    console.error("Invalid signature");
  }

  return isValid;
};

app.get("/", (req: Request, res: Response) => {
  res.status(200).json({ message: "Server is running" });
});
//checkking webhook
app.post("/webhook", (req: Request, res: Response) => {
  if (verifySignature(req)) {
    const event = req.headers["x-github-event"];
    const payload = req.body;

    console.log(`Received GitHub event: ${event}`);
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
