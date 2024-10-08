import { Request, Response } from "express";
import { fetchGithubRepositories } from "../services/githubService";

export const getUserRepos = async (req: Request, res: Response) => {
  const { username } = req.params;
  try {
    const repos = await fetchGithubRepositories(username);
    res.status(200).json({
      success: true,
      data: repos,
    });
  } catch (error) {
    if (error instanceof Error) {
      res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  }
};
