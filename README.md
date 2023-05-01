# licor-backend

## GitHub API Caller

Before running the `gh_caller.py` file, you need to set up the following environment variables in the `.env` file:

1. `TARGET_USERNAME`: This is the username of the target user for whom you want to retrieve information.
2. `GH_APP_ID`: This is the ID of your GitHub app that you have created.
3. `GH_APP_PRIVATE_KEY_PATH`: This is the path to the private key file for your GitHub app.

You should also create a logging directory in the project folder by running the following command:

```bash
mkdir -p logs/gh_requests/
```

This command will create the necessary directory structure for storing log files. This is important for keeping a record of all the requests made to the GitHub API.

Once the environment variables are set and the log directory is created, you can run the gh_api.py file to retrieve information about the target user's GitHub repositories.
