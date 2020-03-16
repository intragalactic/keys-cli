## keys - keys.cm client

This is the keys core client, which can be installed with npm and provides the `keys` command line utility.

[https://keys.cm](https://keys.cm) is a repository that stores encrypted blobs of environment variables. You can store
variable sets for your software in the repository, and fetch-decrypt-load them at runtime. This prevents your sensitive environment variables like API access keys from ever having to sit in plain text files on your systems and developer machines.

The repository functions similarly to modern password managers, and keys.cm does not have access to your environment
variables, they are decrypted locally after you fetch the blob. Don't lose your password!

### Prerequisites

You should have an account at [https://keys.cm](https://keys.cm) if you want to interact with the repository.

#### Linux Build Dependencies
Before `npm install`, you may have to install `python2` and `libsecret`

```bash
sudo apt-get install libsecret-1-dev # Debian/Ubuntu
sudo yum install libsecret-devel # Red Hat-based
sudo pacman -S libsecret # Arch Linux
```

### Installing

Install the package with npm. This will provide a new command in your shell, called `keys`

```
npm install -g keys-cli
```

### Usage

Just prefix any command you want to run with `keys`. Environment variables will be downloaded, decrypted, and your
command will be executed, now having access to them.

```bash
$ keys ./anything.sh -a 1 -b 2
keys 2.2.6
Loaded credentials from keychain
AuthSuccess for user@example.com
DEV                        TEST               PROD
[1] goolybib-dev           [5] goolybib-test  [7] optimoji-prod
[2] microservice-prototype [6] sliceline-test [8] sliceline-prod
[3] optimoji-dev
[4] sliceline-dev
Load Environment #: 2
Executing: ./anything.sh -a 1 -b 2 # process now has access to AWS_SECRET_ACCESS_KEY
```

```bash
$ keys java -jar mything.jar
```

```bash
$ keys gunicorn app:app
```

```bash
$ keys bin/rails server -e production -p 4000
```

### Options

`-e | --environment environment-name`
Specifies the environment to load, skipping the prompt which asks for it.

`-v | --verbose`
Enable verbose mode, printing debugging messages about what is going on.

`-c | --clean`
By default, keys will append environment variables to your current shell environment before running your command.
This flag will run your command with _only_ the variables from the selected environment.

`-i | --import`
Pipe lines of variables key=value into stdin to import variables to an environment specified by `-e`.
*This will overwrite the environment*

```
echo "VAR1=ABC\nVAR2=DEF" | keys -i -e myenv
```

```
heroku config -s | keys -i -e myenv
```

`-t | --token`
specifies that the KEYS_TOKEN variable in the local environment should be read for an access token for
a specific environment. This will bypass normal username/password authentication.

```
KEYS_TOKEN=abc123 keys -t command
```

`--reset`
Reset credentials and settings from ~/.keys/settings.json

### Access Tokens

Sometimes you need to execute things non-interactively. Create an access token for a specific environment at
[https://keys.cm](https://keys.cm) and use that instead of username/password. This is less secure than
interactive authentication, but the server/container state, IP address, and other system data are used to detect
suspicious circumstances and deny access and/or notify you appropriately.

```bash
$ keys -t env_access_token ./start-my-software.sh -myoption myvalue
```

...or in the local environment:

```bash
$ KEYS_TOKEN=env_access_token keys -t ./start-my-software.sh -myoption myvalue
```

## License

This project is licensed under the GNU General Public License v3.0


