#!/usr/bin/env node

const request = require('request-promise');
let {
    SHA3
} = require('sha3');
const cryptico = require('cryptico');
const crypto = require('sjcl');
const promptly = require('promptly');
const fs = require('fs');
const _ = require('lodash');
const colors = require('colors'); // eslint-disable-line no-unused-vars
const exec_await = require('await-exec');
const keytar = require('keytar')

const {
    exec,
    spawn
} = require('child_process');

let default_settings = {
    default_environment: null,
    ask_everytime: false,
    self_update: false
};

let model = {
    debug: false,
    client: {
        version: '2.1.0',
        endpoint: 'https://api.keys.cm'
    },
    args: [],
    cmd: [],
    settings: _.cloneDeep(default_settings),
    creds: {}
};

// let stdout = process.stdout;
// process.stdout.write = process.stderr.write;

process.on('SIGINT', function () {
    process.exit(1);
});

let error = (...messages) => {
    let line = '';
    _.each(messages, (m, i) => {
        line += i == 0 ? `${m} `.red : `${m} `;
    });
    console.error(line);
};

let die = (...messages) => {
    error(...messages);
    process.exit(1);
}

let info = (message) => {
    console.error(message);
};

let success = (...messages) => {
    let line = '';
    _.each(messages, (m, i) => {
        line += i == 0 ? `${m} `.green : `${m} `;
    });
    console.error(line);
};

let debug = (message) => {
    if (model.debug) {
        console.error(message.grey);
    }
};

let unstore_creds = (model) => {
    if (model.settings.email) {

        keytar.deletePassword('keys.cm', model.settings.email);
        // if (process.platform === 'darwin') {
        //     let cmd = `delete-generic-password -a ${model.settings.email} -s keys.cm`;
        //     exec(cmd, (err, stdout, stderr) => {
        //         if (err) {
        //             debug("Error removing credentials from keychain");
        //         } else {
        //             debug("Removed credentials from keychain");
        //         }
        //     });
        // }
    }
}

let store_creds = (creds) => {

    keytar.setPassword('keys.cm', creds.email, creds.passwd )

    // if (process.platform === 'darwin') {
    //     if (creds.email && creds.passwd) {
    //         let cmd = `security add-generic-password -a ${creds.email} -s keys.cm -w ${creds.passwd}`;
    //         exec(cmd, (err, stdout, stderr) => {
    //             if (err) {
    //                 debug("Error storing credentials in keychain");
    //             } else {
    //                 debug("Saved credentials in keychain");
    //             }
    //         });
    //     }
    // }
}

let load_creds = async (model) => {

    if (!model.token) {
        if (model.settings.email) {

            let creds = await keytar.findCredentials('keys.cm');
            if ( creds ){
                let match = _.find(creds, {'account': model.settings.email });
                if (match) {
                    model.creds.email = model.settings.email;
                    model.creds.passwd = match.password;
                }
            }

            // if (process.platform === 'darwin') {
            //     let cmd = `security find-generic-password -a ${model.settings.email} -s keys.cm -g`;
            //     let out = await exec_await(cmd);
            //     let m = /password:\s+"(.*)"/g.exec(out.stderr);
            //     if (m && m.length > 1) {
            //         model.creds.email = model.settings.email;
            //         model.creds.passwd = m[1];
            //         debug("Loaded credentials from keychain");
            //     }
            // } else {
            //     debug("Can't load stored credentials on this platform");
            // }
        } else {
            debug("Skipping credentials load from platform, no default account set");
        }
    } else {
        debug("Skipping credentials load from platform, using token instead.");
    }
    return Promise.resolve(model);
}

let print_intro = (model) => {
    if (model.client.version === model.latest) {
        success('keys', `${model.client.version} ` + `(latest) ${model.client.endpoint}`.grey);
    } else {
        success('keys', `${model.client.version} ` + `(latest is ${model.latest}) ${model.client.endpoint}`.grey);
    }
    debug('Options: ' + _.join(model.args, ' '));
    return Promise.resolve(model);
};

let self_update = (model) => {

    return request.get(model.client.endpoint + '/info').then((body) => {

        let info = JSON.parse(body)
        model.latest = info.version;

        if (_.has(info, 'news')) {
            info(...info.news);
        }

        if (!model.settings.self_update) {
            return Promise.resolve(model);
        }

        if (_.includes(process.argv[0], 'node')) {
            debug('Running as a non-binary script, skipping self-update.');
            return Promise.resolve(model);
        } else if (model.version == model.latest) {
            return Promise.resolve(model);
        } else {

            return exec('uname', function (error, stdout) {
                if (error) throw error;
                let uname = _.trim(_.toLower(stdout));
                let myself = null;

                return request.get(model.client.endpoint + `/dist/bin/${uname}/keys`, {
                    encoding: null
                }).then((bin) => {
                    myself = process.argv[0];
                    fs.writeFileSync(myself, bin, {
                        encoding: null
                    });
                    return Promise.resolve(model);
                });
            });
        }
    }).catch(err => {
        die(`Could not reach endpoint ${model.client.endpoint}`);
    });
};

let update_config = (model) => {
    let file = process.env.HOME + '/.keys/settings.json';
    fs.writeFileSync(file, JSON.stringify(model.settings), {
        encoding: 'utf-8'
    });
    return Promise.resolve(model);
};

let handle_args = (model) => {

    let items = _.drop(process.argv, 2);
    let start_cmd = false;
    let last_was_token = false
    let last_was_env = false
    let clean = false;
    _.each(items, (item) => {
        if (!start_cmd) {
            if (_.startsWith(item, '-')) {
                if ((item === '-t' || item === '--token') && !process.env.KEYS_TOKEN) {
                    last_was_token = true;
                } else if (item === '-v' || item === '--verbose') {
                    model.debug = true;
                } else if (item === '-e' || item === '--environment') {
                    last_was_env = true
                } else if (item === '--clean') {
                    clean = true;
                }
                model.args.push(item);
            } else if (last_was_token) {
                model.args.push(item);
                last_was_token = false;
            } else if (last_was_env) {
                model.args.push(item);
                last_was_env = false;
            } else {
                start_cmd = true;
                model.cmd.push(item);
            }
        } else {
            model.cmd.push(item);
        }
    });

    if (clean) {
        unstore_creds(model);
        model.settings = _.cloneDeep(default_settings);
        update_config(model);
        info("Configuration Reset");
        process.exit(0);
    }

    model.cmd = _.join(model.cmd, ' ');
    let index = _.findIndex(model.args, (arg) => arg === '-t' || arg === '--token');

    if (index > -1) {
        if (process.env.KEYS_TOKEN) {
            info('Using auth from KEYS_TOKEN environment variable'.grey);
            model.token = process.env.KEYS_TOKEN;
        } else {
            if (model.args.length > index + 1) {
                model.token = model.args[index + 1];
            } else {
                die("-t|--token requires token as an argument (or KEYS_TOKEN environment variable set)");
            }
        }
    }

    if (process.env.KEYS_ENDPOINT) {
        debug('Using endpoint ' + process.env.KEYS_ENDPOINT + ' from KEYS_ENDPOINT environment variable')
        model.client.endpoint = process.env.KEYS_ENDPOINT;
    }

    return Promise.resolve(model);
}

let load_config = (model) => {

    let dir = process.env.HOME + '/.keys';
    let file = dir + '/settings.json';

    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }

    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify(model.settings), {
            encoding: 'utf-8'
        });
    }

    let content = fs.readFileSync(file, 'utf-8');
    _.assign(model.settings, JSON.parse(content));
    return Promise.resolve(model);
};

let host_info = async (model) => {

    model.client.type = 'default';

    let uname = await exec_await('uname -a');
    let hash = new SHA3(512);
    hash.update(uname.stdout);
    model.client.uname_hash = hash.digest('hex');

    hash = new SHA3(512);
    hash.update(model.cmd);
    model.client.cmd_hash = hash.digest('hex');

    // _.filter(process.env, ) look for heroku vars

    // cat /proc/1/cgroup to detect if inside docker/lxc/container
    // https://stackoverflow.com/questions/20010199/how-to-determine-if-a-process-runs-inside-lxc-docker

    return Promise.resolve(model);
};

let ask_creds = async (model) => {

    if (model.token) {
        debug('Auth token provided, skipping credential prompt.');
        model.creds.token = model.token;
    } else if (!model.creds.email || !model.creds.passwd) {

        let text = 'Email: ';
        let email_options = {
            output: process.stderr
        };
        let passwd_options = {
            silent: true,
            output: process.stderr
        };

        if (_.has(model.settings, 'email')) {
            text = `Email [${model.settings.email}]:`;
            email_options.default = model.settings.email;
        }

        model.creds.email = await promptly.prompt(text, email_options);

        if (!model.creds.email || !model.creds.email.length) {
            model.creds.email = model.setttings.email;
        } else {
            model.settings.email = model.creds.email;
            let file = process.env.HOME + '/.keys/settings.json';
            fs.writeFileSync(file, JSON.stringify(model.settings), {
                encoding: 'utf-8'
            });
        }

        model.creds.passwd = await promptly.prompt('Password: ', passwd_options);
    }

    return Promise.resolve(model);
};

let ask_env = async (model) => {

    if (model.token) {
        model.selected = _.findKey(model.org.envs, () => true);
    } else if (model.env_name) {
        model.selected = _.find(model.org.envs, {
            name: model.env_name
        });
    }

    if (model.selected) {
        info(`Loading environment: ${model.org.envs[model.selected].name}`);
        return Promise.resolve(model);
    } else {
        let text = 'Choose the environment to load:\n';
        let i = 1;
        let options = {};
        let envs = _.map(model.org.envs, (env) => {
            return env;
        });
        _.each(envs, (env) => {
            text += `[${i++}] ${env.name}\n`;
        });
        let env_index = await promptly.prompt(text, options);
        if (env_index > 0 && envs.length >= env_index) {
            model.selected = envs[env_index - 1].id;
            // model.settings.default_environment = model.selected;
            return Promise.resolve(model);
        } else {
            error('invalid index');
        }
    }
};

let execute = (model) => {

    let env = _.clone(process.env);
    _.each(model.org.envs[model.selected].vars, (v, k) => {
        env[k] = v.value;
    });

    if (_.trim(model.cmd).length < 1) {
        info('');
        info('Typical usage is:');
        info('  keys [command you want to run with the environment vars loaded]');
        info('');
        info('No command was provided, exiting. ');
    } else {
        success('Executing:', model.cmd);
        spawn(model.cmd, {
            stdio: 'inherit',
            shell: true,
            env: env,
        });
    }

    return Promise.resolve();
};

let login = async (model) => {

    let req = {
        client: model.client
    };

    if (_.has(model.creds, 'email')) {
        req.email = model.creds.email;
    }

    if (_.has(model.creds, 'passwd')) {
        let hash = new SHA3(512);
        hash.update(model.creds.passwd);
        req.passwd_hash = hash.digest('hex');
    }

    if (_.has(model.creds, 'token')) {
        let hash = new SHA3(512);
        hash.update(model.creds.token);
        req.token_hash = hash.digest('hex');
    }

    return request.post(model.client.endpoint + '/login', {
        json: req
    }).then(async (body) => {

        if (_.has(body, '2fa') && body['2fa']) {
            let twofactor_options = {
                output: process.stderr
            };
            let code = await promptly.prompt('2FA Code: ', twofactor_options);

            req = {
                user: body['user'],
                code: code
            }
            return request.post(model.client.endpoint + '/totp/login', {
                json: req
            }).then((body) => {

                success('AuthSuccess', `for ${model.creds.email}`);
                _.merge(model, body);

                store_creds(model.creds);
                return Promise.resolve(model);

            }).catch(err => {
                console.error(err.message);
                die('AuthFailed', 'Invalid 2FA Code');
            });

        } else {

            success('AuthSuccess', `for ${model.creds.email}`);
            _.merge(model, body);

            return Promise.resolve(model);
        }

    }).catch(err => {
        console.error(err.message);
        if (model.token) {
            die('AuthFailed', 'Invalid Token');
        } else {
            die('AuthFailed', 'Bad Username/Password');
        }
    });
};

let decrypt_model = (model) => {

    let passwd = _.has(model.creds, 'token') ? model.creds.token : model.creds.passwd;
    let org_key_ct = _.has(model, 'org_key_ct') ? model.org_key_ct : model.user.org_keys_ct[model.org.id];

    let keypair, result, org_key;

    if (_.has(model.creds, 'token')) {
        org_key = crypto.decrypt(passwd, JSON.stringify(org_key_ct));
    } else {
        keypair = cryptico.generateRSAKey(passwd, 1024);
        result = cryptico.decrypt(org_key_ct, keypair);
        org_key = result.plaintext;
    }

    // TODO handle result.failure

    _.each(model.org.envs, (env, id) => {
        if (model.token && (!_.has(model, 'selected') || !model.selected)) {
            model.selected = id;
        }
        model.org.envs[id].vars = JSON.parse(crypto.decrypt(org_key, env.vars_ct));
    });

    return Promise.resolve(model);
};

let specials = (model) => {

    let parts = _.chain(model.cmd).toLower().words().value();
    let vars = model.org.envs[model.selected].vars;

    if (parts.length && parts[0] === 'docker') {
        _.each(vars, (val, key) => {
            model.cmd += ` -e ${key}`;
        });
    }

    return Promise.resolve(model);
};

let main = async () => {

    console.error(process.platform);

    self_update(model)
        .then(print_intro)
        .then(load_config)
        .then(handle_args)
        .then(load_creds)
        .then(ask_creds)
        .then(host_info)
        .then(login)
        .then(decrypt_model)
        .then(ask_env)
        .then(update_config)
        .then(specials)
        .then(execute)
        .catch((err) => {
            console.trace(err.message);
        });
};

if (require.main === module) {
    main();
}