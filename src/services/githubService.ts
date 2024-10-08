import axios from "axios";

const GITHUB_API_BASE_URL = "https://api.github.com";

export const fetchGithubRepositories = async (username: string) => {
  try {
    const token = process.env.GITHUB_API_TOKEN;
    const response = await axios.get(
      `${GITHUB_API_BASE_URL}/users/${username}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    return response.data;
  } catch (error) {
    if (error instanceof Error) {
      console.error("Error fetching GitHub repositories:", error.message);
      throw new Error("Failed to fetch GitHub repositories");
    }
  }
};
