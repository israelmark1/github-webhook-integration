import express, { Request, Response } from "express";
import dotenv from "dotenv";
import { json } from "body-parser";
import { getUserRepos } from "./controllers/githubController";

dotenv.config();

const app = express();
const port = process.env.PORT || 8000;


app.use(json());

app.post("/webhook", (req: Request, res: Response) => {
    const event = req.headers["x-github-event"];
    const payload = req.body;

    console.log(`Received github event: ${event}`);
    if (event === "push") {
        console.log("Received push event:", payload);
    }
    res.status(200).send("Webhook received");
})

app.get("/github/:username", getUserRepos);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});