# Before testing

1. Add config file to `./config/.env` (see an example in the `./config/.env.example`).
   - By default, this app use port `44044`. If you set another port please update `SERVER_PORT` in the `Makefile`.
2. Set path to config:
    ```
    export CONFIG_PATH=./config/.env
    ```
3. Set database type (supported types – postgres or mongo):
   ```bash
   export DB_TYPE=postgres
   ```

   Set URL for Database:
   ```bash
   export POSTGRESQL_URL='postgres://login:password@host:port/db_name?sslmode=disable'
   # or if you use mongo:
   export MONGO_URL='mongodb+srv://login:password@cluster.mongodb.net/?retryWrites=true&w=majority&appName=Cluster'
   ```
4. If you use S3 for key storage you need to copy `app_test-app-id_private.pem` from the `certs` folder and upload to your S3 bucket.
5. Run tests — `make test-all-app` or `make test-api`. You'll run database migrations, insert test-app into database, run the server and then run tests.

For more details you can check other commands in the `Makefile`.