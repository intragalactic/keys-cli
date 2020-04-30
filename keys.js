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
const keytar = require('keytar');
const get_stdin = require('get-stdin');
const moment = require('moment');
const uuid = require('uuid/v4');
const spinner = require('cli-spinner').Spinner;
const columnify = require('columnify');
const URL = require('url').URL;

const {
    exec,
    spawn
} = require('child_process');

let default_settings = {
    default_environment: null,
    ask_everytime: false,
    self_update: false,
    registered: false,
    endpoint: 'https://keys.cm'
};

let model = {
    debug: false,
    client: {
        version: '2.3.1'
    },
    args: [],
    cmd: [],
    settings: _.cloneDeep(default_settings),
    creds: {},
    reset: false,
    clean: false,
    import: false,
    fresh: false,
    local: false
};

// let stdout = process.stdout;
// process.stdout.write = process.stderr.write;

process.on('SIGINT', function() {
    process.exit();
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

let info = (...messages) => {
    let line = '';
    _.each(messages, (m) => {
        line += `${m} `;
    });
    console.error(line);
};

let debug = (message) => {
    if (model.debug) {
        console.error(message.grey);
    }
};

let validURL = (s) => {
    try {
        new URL(s);
        return true;
    } catch (err) {
        return false;
    }
};

let unstore_creds = (model) => {
    if (model.settings.email) {
        keytar.deletePassword('keys.cm', model.settings.email);
    }
}

let store_creds = (creds) => {
    if (!model.creds.token) {
        keytar.setPassword('keys.cm', creds.email, creds.passwd);
    }
}

let load_creds = async(model) => {
    if (model) {
        if (!model.token) {
            if (model.settings.email) {
                let creds = await keytar.findCredentials('keys.cm');
                if (creds) {
                    let match = _.find(creds, {
                        'account': model.settings.email
                    });
                    if (match) {
                        debug('Loaded credentials from keychain');
                        model.creds.email = model.settings.email;
                        model.creds.passwd = match.password;
                    }
                }
            } else {
                debug("Skipping credentials load from platform, no default account set");
            }
        } else {
            debug("Skipping credentials load from platform, using token instead.");
        }
    }
    return Promise.resolve(model);
}

let print_intro = (model) => {

    if (model) {
        model.spinner.stop();

        if (model.client.version === model.latest) {
            info(`${model.client.version} ` + `(latest) ${model.client.endpoint}`.grey);
        } else {
            let latest = model.latest ? `(latest is ${model.latest})` : '';
            let endpoint = model.local ? '(local mode)' : model.client.endpoint;
            info(`${model.client.version} ${latest} ${endpoint}`.grey);
        }
        debug('Options: ' + _.join(model.args, ' '));
    }
    return Promise.resolve(model);
};

let self_update = (model) => {

    if (model) {
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

                return exec('uname', function(error, stdout) {
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
            debug(`\nCould not reach endpoint ${model.client.endpoint} during self_update`);
            return Promise.resolve(model);
        });
    } else {
        return Promise.resolve(null);
    }
};

let update_config = (model) => {
    if (model) {
        let file = process.env.HOME + '/.keys/settings.json';
        fs.writeFileSync(file, JSON.stringify(model.settings, null, '  '), {
            encoding: 'utf-8'
        });
    }
    return Promise.resolve(model);
};

let cache_model = (model) => {
    if (model) {
        let file = process.env.HOME + '/.keys/cache.json';
        let cache = {}
        cache.user = _.cloneDeep(model.user);
        cache.orgs = _.cloneDeep(model.orgs);
        cache.org = _.cloneDeep(model.org);
        fs.writeFileSync(file, JSON.stringify(cache), {
            encoding: 'utf-8'
        });
    }
};

let capture_stdin = async(model) => {
    if (model) {
        await get_stdin().then(str => {
            model.input = str;
        });
    }
    return Promise.resolve(model);
};

let handle_args = (model) => {

    let items = _.drop(process.argv, 2);
    let start_cmd = false;
    let last = {
        token: false,
        environment: false,
        endpoint: false
    }
    _.each(items, (item) => {
        if (!start_cmd) {
            if (_.startsWith(item, '-')) {
                if ((item === '-t' || item === '--token') && !process.env.KEYS_TOKEN) {
                    last.token = true;
                } else if (item === '-v' || item === '--verbose') {
                    model.debug = true;
                } else if (item === '-e' || item === '--environment') {
                    last.environment = true;
                } else if (item === '-c' || item === '--clean') {
                    model.clean = true;
                } else if (item === '-l' || item === '--local') {
                    model.local = true;
                } else if (item === '-i' || item === '--import') {
                    model.import = true;
                } else if (item === '--register') {
                    model.fresh = true;
                } else if (item === '--endpoint') {
                    last.endpoint = true;
                } else if (item === '--reset') {
                    model.reset = true;
                }
                model.args.push(item);
            } else if (last.token) {
                model.args.push(item);
                last.token = false;
            } else if (last.environment) {
                model.env_name = item;
                last.environment = false;
            } else if (last.endpoint) {
                if (validURL(item)) {
                    model.client.endpoint = item;
                } else {
                    die('\nERROR'.red, '--endpoint requires a valid URL argument.');
                }
                last.endpoint = false;
            } else {
                start_cmd = true;
                model.cmd.push(item);
            }
        } else {
            model.cmd.push(item);
        }
    });

    _.each(last, (v, k) => {
        if (v) {
            if (k == 'token') {
                die('\nERROR'.red, `--${k} requires an argument ( or set KEYS_TOKEN in local environment)`);
            }
            die('\nERROR'.red, `--${k} requires an argument`);
        }
    });

    if (model.reset) {
        unstore_creds(model);
        model.settings = _.cloneDeep(default_settings);
        update_config(model);
        info('');
        info('Configuration Reset'.yellow);
        model.spinner.stop();
        return Promise.resolve(null);
    } else {
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
}

let load_cache = (model) => {
    if (model) {
        let file = process.env.HOME + '/.keys/cache.json';
        if (fs.existsSync(file)) {
            let content = fs.readFileSync(file, 'utf-8');
            let cache = JSON.parse(content);
            _.merge(model, cache);
            return Promise.resolve(model);
        } else {
            console.error('No cache to load from, sorry.');
        }
    }
}

let load_config = (model) => {

    if (model) {
        let dir = process.env.HOME + '/.keys';
        let file = dir + '/settings.json';

        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
            model.fresh = true;
        }

        if (!fs.existsSync(file)) {
            fs.writeFileSync(file, JSON.stringify(model.settings), {
                encoding: 'utf-8'
            });
            model.fresh = true;
        }

        let content = fs.readFileSync(file, 'utf-8');
        _.assign(model.settings, JSON.parse(content));

        model.client.endpoint = model.settings.endpoint;

        if (!model.settings.registered) {
            model.fresh = true;
        }
    }
    return Promise.resolve(model);
};

let host_info = async(model) => {

    if (model) {
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
    }
    return Promise.resolve(model);
};

let ask_creds = async(model) => {

    if (model) {
        if (model.token) {
            debug('Auth token provided, skipping credential prompt.');
            model.creds.token = model.token;
        } else {

            if (model.fresh) {
                info('');
                let ask = 'Set up a new repository? [Y/n]';
                let register_options = {
                    output: process.stderr,
                    default: 'Y'
                };
                let answer = await promptly.prompt(ask, register_options);
                if (answer === 'Y' || answer === 'y') {

                    info('Creating new account...'.grey);

                    let email_options = {
                        output: process.stderr
                    };
                    let email = await promptly.prompt('Email: ', email_options);

                    let passwd_options = {
                        silent: true,
                        output: process.stderr
                    };
                    let passwd = await promptly.prompt('Password: ', passwd_options);
                    let confirm = await promptly.prompt('Confirm Password: ', passwd_options);

                    if (passwd === confirm) {

                        let org_key = uuid();
                        let keypair = cryptico.generateRSAKey(passwd, 1024);
                        let public_key = cryptico.publicKeyString(keypair);
                        let hash = new SHA3(512);
                        hash.update(passwd);

                        let body = {
                            public_key: public_key,
                            org_key_ct: cryptico.encrypt(org_key, public_key).cipher
                        };
                        body['passwd_hash'] = hash.digest('hex');
                        body['email'] = email;

                        let sample_vars = {
                            'AWS_ACCESS_KEY_ID': {
                                'value': 'abc123',
                                'updated': moment().unix(),
                            },
                            'AWS_SECRET_ACCESS_KEY': {
                                'value': 'xyz456',
                                'updated': moment().unix(),
                            },
                            'AWS_DEFAULT_REGION': {
                                'value': 'us-east-1',
                                'updated': moment().unix(),
                            }
                        };
                        body['vars_ct'] = crypto.encrypt(org_key, JSON.stringify(sample_vars));

                        let options = {
                            uri: model.client.endpoint + '/register',
                            jar: true,
                            json: body,
                            method: 'POST'
                        };
                        return request(options).then((body) => {
                            info('Created Account'.green, `at ${model.client.endpoint}`.grey);
                            model.settings.registered = true;
                            model.creds.email = email;
                            model.creds.passwd = passwd;
                            model.settings.email = model.creds.email;
                            return Promise.resolve(model);
                        }).catch((err) => {
                            error(err);
                            return Promise.resolve(null);
                        });

                    } else {
                        error('Passwords did not match');
                        return Promise.resolve(null);
                    }

                } else {
                    model.fresh = false;
                    info('Log into existing account...'.grey);
                }
            }

            if (!model.fresh && (!model.creds.email || !model.creds.passwd)) {

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

                try {
                    model.creds.email = await promptly.prompt(text, email_options);
                } catch (e) {
                    console.error(e);
                    process.exit();
                }

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
        }
    }

    return Promise.resolve(model);
};

let import_env = async(model) => {
    if (model && model.import) {
        let import_vars = {};
        if (model.input) {
            let lines = model.input.split('\n');
            _.each(lines, (line) => {
                if (line.replace(/\s/g, '').length) {
                    let parts = line.split('=');
                    if (parts.length != 2) {
                        info('Skipping line'.yellow, 'bad format: ' + line);
                    } else {
                        let key = parts[0];
                        let val = parts[1];
                        if ('\'"'.includes(val[0]) && val.slice(-1) === val[0]) {
                            val = val.substring(1, val.length - 1);
                        }
                        import_vars[key] = {
                            value: val,
                            updated: moment().unix(),
                            by: model.user.id
                        }
                    }
                }
            });
        }

        let body = {
            vars_ct: crypto.encrypt(model.user.org_keys[model.user.org], JSON.stringify(import_vars))
        }
        if (model.create_env) {
            model.selected = uuid();
            body.id = model.selected;
            body.name = model.env_name;
        } else {
            body.id = model.selected;
        }
        let options = {
            uri: model.client.endpoint + '/env/update',
            jar: true,
            json: body,
            method: 'POST'
        };
        return request(options).then((body) => {
            let action = model.create_env ? 'Created' : 'Updated';
            info(action.yellow, model.env_name.bold, `with ${_.size(import_vars)} variables from stdin`);
            return Promise.resolve(null);
        }).catch((err) => {
            error(err);
            return Promise.resolve(null);
        });
    } else {
        return Promise.resolve(model);
    }
}

let update_stats = async(model) => {

    if (!model.local && model && model.selected && !model.creds.token) {

        let body = {
            id: model.selected,
            accessed: moment().unix(),
            selected: true
        }

        let options = {
            uri: model.client.endpoint + '/env/update',
            jar: true,
            json: body,
            method: 'POST'
        };
        request(options).catch(err => error(err));
    }

    return Promise.resolve(model);
};

let ask_env = async(model) => {

    if (model) {
        if (model.token) {
            model.selected = _.findKey(model.user.envs, () => true);
        } else if (model.env_name) {
            let found = _.find(model.user.envs, {
                name: model.env_name
            });
            if (found) {
                model.selected = found.id;
            } else {
                if (model.import) {
                    model.create_env = true;
                } else {
                    info('NotFound'.yellow, model.env_name);
                }
            }
        }

        if (model.selected) {
            if (!model.import) {
                info(`Loading environment: ${model.user.envs[model.selected].name}`);
            }
            return Promise.resolve(model);
        } else {
            if (!model.import) {
                let options = {};
                let envs_all = _.map(model.user.envs, (env) => {
                    return env;
                });
                let envs = {
                    dev: _.filter(envs_all, { stage: 'dev' }),
                    test: _.filter(envs_all, { stage: 'test' }),
                    qa: _.filter(envs_all, { stage: 'qa' }),
                    prod: _.filter(envs_all, { stage: 'prod' })
                }
                let choices = {
                    dev: 1,
                    test: 1 + envs.dev.length,
                    qa: 1 + envs.dev.length + envs.test.length,
                    prod: 1 + envs.dev.length + envs.test.length + envs.qa.length
                }
                let env_choice = {};
                let rows = [];
                for (let i = 0; i < envs_all.length; i++) {
                    let row = {}
                    _.each(['dev', 'test', 'qa', 'prod'], (stage) => {
                        let next = _.pullAt(envs[stage], [0]);
                        if (next.length > 0 && next[0]) {
                            row[stage] = `[${choices[stage]}] ${next[0].name}\n`;
                            env_choice['' + choices[stage]++] = next[0].id;
                        }
                    });
                    if (_.keys(row).length > 0) {
                        rows.push(row);
                    }
                }

                let columns = columnify(rows);
                info(columns);
                info();
                text = `Load Environment #: `;
                let env_index = await promptly.prompt(text, options);
                if (env_index > 0 && _.keys(env_choice).length >= env_index) {
                    model.selected = env_choice[env_index];
                    return Promise.resolve(model);
                } else {
                    error('Invalid Selection');
                }
            } else {
                if (model.create_env) {
                    return Promise.resolve(model);
                } else {
                    info('Use', '-e name'.yellow, 'with', '-i'.yellow, 'to specify an environment to create/update');
                    info('  with the lines from stdin (name=value)');
                    return Promise.resolve(null);
                }
            }
        }
    }
};

let execute = (model) => {

    if (model) {
        let env = {}
        let shell = false;

        if (!model.clean) {
            env = _.clone(process.env);
            shell = true;
        }

        _.each(model.user.envs[model.selected].vars, (v, k) => {
            env[k] = v.value;
        });

        if (_.trim(model.cmd).length < 1) {
            info('');
            info('Typical usage is:');
            info('  keys [command you want to run with the environment variables loaded]');
            info('');
            info('No command was provided, exiting. ');
        } else {
            info('Executing'.green, model.cmd);
            spawn(model.cmd, {
                stdio: 'inherit',
                shell: shell,
                env: env,
            });
        }
    }

    return Promise.resolve();
};

let login = async(model) => {

    if (model) {
        if (model.local) {
            return load_cache(model);
        } else {
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
            let options = {
                uri: model.client.endpoint + '/login',
                jar: true,
                json: req,
                method: 'POST'
            };
            return request(options).then(async(body) => {

                model.settings.endpoint = model.client.endpoint;

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

                        info('AuthSuccess'.green, `for ${model.creds.email}`.grey);
                        _.merge(model, body);
                        model.settings.registered = true;

                        store_creds(model.creds);
                        return Promise.resolve(model);

                    }).catch(err => {
                        console.error(err.message);
                        die('AuthFailed', 'Invalid 2FA Code');
                    });

                } else {
                    let auth_for = model.creds.token ? 'token' : model.creds.email;
                    info('AuthSuccess'.green, `for ${auth_for}`.grey);
                    model.settings.registered = true;
                    _.merge(model, body);
                    cache_model(model);
                    store_creds(model.creds);

                    return Promise.resolve(model);
                }

            }).catch(err => {
                if (err.statusCode) {
                    console.error('HTTP Error', err.statusCode);
                }
                if (err.statusCode === 401) {
                    if (model.token) {
                        die('AuthFailed', 'Invalid Token');
                    } else {
                        die('AuthFailed', 'Bad Username/Password');
                    }
                }
                error('WARN'.yellow, `Failure to reach ${model.client.endpoint}, entering --local mode.`)
                model.local = true;
                return load_cache(model);
            });
        }
    } else {
        return Promise.resolve(model);
    }
};

let decrypt_model = (model) => {

    if (model) {
        let passwd = _.has(model.creds, 'token') ? model.creds.token : model.creds.passwd;
        // let org_key_ct = _.has(model, 'org_key_ct') ? model.org_key_ct : model.user.org_keys_ct[model.org.id];

        // let keypair, result;

        if (_.has(model.creds, 'token')) {
            // org_key = crypto.decrypt(passwd, JSON.stringify(org_key_ct));
            model.user.org_keys = {};
            _.each(model.user.org_keys_ct, (org_key_ct, orgid) => {
                model.user.org_keys[orgid] = crypto.decrypt(passwd, org_key_ct);
            });
        } else {

            let keypair = cryptico.generateRSAKey(passwd, 1024);
            // result = cryptico.decrypt(org_key_ct, keypair);
            // model.user.org_key = result.plaintext;

            if (_.has(model.user, 'org_keys_ct')) {
                model.user.org_keys = {};
                _.each(model.user.org_keys_ct, (org_key_ct, orgid) => {
                    model.user.org_keys[orgid] = cryptico.decrypt(org_key_ct, keypair).plaintext;
                });
            }
        }

        _.each(model.user.envs, (env, id) => {
            if (model.token && (!_.has(model, 'selected') || !model.selected)) {
                model.selected = id;
            }
            if (env.vars_ct) {
                model.user.envs[id].vars = JSON.parse(crypto.decrypt(model.user.org_keys[env.org], env.vars_ct));
            }
        });
    }

    return Promise.resolve(model);
};

let specials = (model) => {

    if (model) {
        let parts = _.chain(model.cmd).toLower().words().value();
        let vars = model.user.envs[model.selected].vars;

        if (parts.length && parts[0] === 'docker') {
            _.each(vars, (val, key) => {
                model.cmd += ` -e ${key}`;
            });
        }
    }

    return Promise.resolve(model);
};

let main = async() => {

    model.spinner = new spinner('%s Initializing ' + 'keys'.green + ' ');
    model.spinner.setSpinnerString(18);
    model.spinner.start();

    load_config(model)
        .then(handle_args)
        .then(self_update)
        .then(capture_stdin)
        .then(print_intro)
        .then(load_creds)
        .then(ask_creds)
        .then(host_info)
        .then(login)
        .then(update_config)
        .then(decrypt_model)
        .then(ask_env)
        .then(update_stats)
        .then(import_env)
        .then(specials)
        .then(execute)
        .catch((e) => {
            model.debug ? console.trace(e) : console.error(e.message.red);
        });
};

if (require.main === module) {
    main();
}