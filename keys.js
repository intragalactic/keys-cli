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
const exec_await = require('await-exec');
const keytar = require('keytar');
const get_stdin = require('get-stdin');
const moment = require('moment');
const uuid = require('uuid').v4;
const ora = require('ora');
const URL = require('url').URL;
const ui = require('./ui');
const liaison = require('./liaison/liaison');
const temp = require('temp');
const child_process = require('child_process');

const {
    exec,
    spawn
} = require('child_process');


let default_settings = {
    default_environment: null,
    ask_everytime: false,
    self_update: false,
    registered: false,
    endpoint: 'https://api.keys.cm'
};

let model = {
    debug: false,
    client: {
        version: '3.0.0'
    },
    args: [],
    cmd: [],
    settings: _.cloneDeep(default_settings),
    creds: {},
    reset: false,
    clean: false,
    import: false,
    fresh: false,
    local: false,
    source: 'keys',
    destination: null
};

// let stdout = process.stdout;
// process.stdout.write = process.stderr.write;

process.on('SIGINT', function () {
    process.exit();
});

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
};

let store_creds = (creds) => {
    try {
        if (!model.creds.token) {
            let p = keytar.setPassword('keys.cm', creds.email, creds.passwd);
            p.then(() => {
                ui.debug('\nStored credentials in keychain');
            }).catch((e) => {
                let platform = process.platform === 'darwin' ? 'OSX' : process.platform;
                ui.error('\nWARN'.yellow, `Unable to store credentials in ${platform} keychain. [Press Enter to Continue]`);
                ui.debug(e.message);
            });
        }
    } catch (e) {
        console.error(e);
    }
};

let load_creds = async (model) => {
    if (model) {
        if (!model.token) {
            if (model.settings.email || model.settings.local) {
                let creds = null;
                try {
                    creds = await keytar.findCredentials('keys.cm');
                } catch (e) {
                    ui.info('WARN'.yellow, 'Unable to load credentials from keychain', 'Run with -v for more info.'.gray);
                    ui.debug(e.message);
                }
                if (creds) {
                    let match = _.find(creds, {
                        'account': model.settings.email
                    });
                    if (match) {
                        ui.debug('Loaded credentials from keychain');
                        model.creds.email = model.settings.email;
                        model.creds.passwd = match.password;
                    }
                }
            } else {
                ui.debug('Skipping credentials load from platform, no default account set');
            }
        } else {
            ui.debug('Skipping credentials load from platform, using token instead.');
        }
    }
    return Promise.resolve(model);
};

let print_intro = (model) => {

    if (model) {

        model.spinner.stop();

        if (model.client.version === model.latest) {
            ui.info('Keys'.green, ` ${model.client.version} ` + `(latest) ${model.client.endpoint}`.grey);
        } else {
            let latest = model.latest ? `(latest is ${model.latest})` : '';
            let endpoint = model.local ? '(local mode)' : model.client.endpoint;
            ui.info('Keys'.green + ` ${model.client.version} ` + `${latest} ${endpoint}`.grey);
        }
        ui.debug('Options: ' + _.join(model.args, ' '));
        ui.debug('Command: ' + model.cmd);
    }

    return Promise.resolve(model);
};

let self_update = (model) => {

    if (model) {
        return request.get(model.client.endpoint + '/info').then((body) => {

            let info = JSON.parse(body);
            model.latest = info.version;

            if (_.has(info, 'news')) {
                ui.info(...info.news);
            }

            if (!model.settings.self_update) {
                return Promise.resolve(model);
            }

            if (_.includes(process.argv[0], 'node')) {
                ui.debug('Running as a non-binary script, skipping self-update.');
                return Promise.resolve(model);
            } else if (model.version === model.latest) {
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
            ui.debug(`\nCould not reach endpoint ${model.client.endpoint} during self_update`);
            ui.debug(err.message);
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
        let cache = {};
        cache.user = _.cloneDeep(model.user);
        cache.orgs = _.cloneDeep(model.orgs);
        cache.org = _.cloneDeep(model.org);
        fs.writeFileSync(file, JSON.stringify(cache), {
            encoding: 'utf-8'
        });
    }
    return Promise.resolve(model);
};

let capture_stdin = async (model) => {
    if (model) {
        await get_stdin().then(str => {
            model.input = str;
        });
    }
    return Promise.resolve(model);
};

let handle_args = async (model) => {

    // model.argv = _.clone(process.argv);
    let items = _.drop(process.argv, 2);

    let start_cmd = false;
    let last = {
        token: false,
        environment: false,
        endpoint: false,
        source: false,
        destination: false
    };

    let endpoint = null;

    ui.debug('\n');

    _.each(items, async (item) => {
        if (!start_cmd) {
            if (_.startsWith(item, '-')) {
                if ((item === '-t' || item === '--token') && !process.env.KEYS_TOKEN) {
                    last.token = true;
                } else if (item === '-v' || item === '--verbose') {
                    ui.set_debug(true);
                } else if (item === '-n' || item === '--name') {
                    last.environment = true;
                } else if (item === '-e' || item === '--edit') {
                   model.edit = true;
                   model.import = true;
                } else if (item === '-c' || item === '--clean') {
                    model.clean = true;
                } else if (item === '-l' || item === '--local') {
                    model.local = true;
                } else if (item === '-i' || item === '--import') {
                    model.import = true;
                } else if (item === '--register') {
                    model.fresh = true;
                } else if (item === '-s' || item === '--source') {
                    last.source = true;
                } else if (item === '-d' || item === '--dest' || item === '--destination') {
                    last.destination = true;
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
            } else if (last.source) {
                last.source = false;
                ui.debug(`Using source ${item}`);
                model.source = liaison.get(item);
            } else if (last.destination) {
                last.destination = false;
                ui.debug(`Using destination ${item}`);
                model.destination = liaison.get(item);
            } else if (last.endpoint) {
                if (validURL(item)) {
                    endpoint = item;
                } else {
                    ui.die('\nError'.red, '--endpoint requires a valid URL argument.');
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

    if (endpoint) {
        if (model.source === 'keys') {
            model.client.endpoint = endpoint;
        } else {
            model.source.endpoint = endpoint;
        }
    }

    _.each(last, (v, k) => {
        if (v) {
            if (k === 'token') {
                ui.die('\nError'.red, `--${k} requires an argument ( or set KEYS_TOKEN in local environment)`);
            }
            ui.die('\nError'.red, `--${k} requires an argument`);
        }
    });

    if (model.reset) {
        await unstore_creds(model);
        model.settings = _.cloneDeep(default_settings);
        await update_config(model);
        ui.info('Success'.green + ' configuration reset to default');
        process.exit(1);
    } else {

        model.cmd = _.join(model.cmd, ' ');

        if (model.destination && model.cmd.trim().length > 0) {
            ui.info('WARN'.yellow, 'Ignoring command', model.cmd.italic, `because we're doing a push to --destination ${model.destination.get_name()}`);
        }

        let index = _.findIndex(model.args, (arg) => arg === '-t' || arg === '--token');

        if (index > -1) {
            if (process.env.KEYS_TOKEN) {
                ui.info('Using auth from KEYS_TOKEN environment variable'.grey);
                model.token = process.env.KEYS_TOKEN;
            } else {
                if (model.args.length > index + 1) {
                    model.token = model.args[index + 1];
                } else {
                    ui.die('-t|--token requires token as an argument (or KEYS_TOKEN environment variable set)');
                }
            }
        }

        if (process.env.KEYS_ENDPOINT) {
            ui.debug('Using endpoint ' + process.env.KEYS_ENDPOINT + ' from KEYS_ENDPOINT environment variable');
            model.client.endpoint = process.env.KEYS_ENDPOINT;
        }

        if (_.trim(model.cmd).length < 1 && !model.destination && !model.fresh && !model.import) {
            ui.info('WARN'.yellow, 'No command was provided.');
            ui.info('');
            ui.info('Some Typical actions are:');
            ui.info('  keys [command]', '# run command with env vars loaded'.gray);
            ui.info('  keys -i', '# create/import a new environment'.gray);
            ui.info('  keys -e', '# edit an existing environment'.gray);
            ui.info('  keys -d [platform]', '# push env vars to destination platform'.gray);
            ui.info('');

            process.exit(0);
        }

        return Promise.resolve(model);
    }
};

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
};

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

        if (!model.settings.registered && !model.settings.local) {
            model.fresh = true;
        }
    }
    return Promise.resolve(model);
};

let host_info = async (model) => {

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

let ask_creds = async (model) => {

    if (model) {
        if (model.token) {
            ui.debug('Auth token provided, skipping credential prompt.');
            model.creds.token = model.token;
        } else {

            if (model.fresh) {
                ui.info('');
                let ask = '[1] Login to an existing account\n';
                ask += '[2] Create a repository on https://keys.cm\n';
                ask += '[3] Create a local repository in $HOME/.keys\n';
                ask += '\nChoose an option: ';
                let register_options = {
                    output: process.stderr,
                    default: '1'
                };
                let answer = await promptly.prompt(ask, register_options);
                if (answer === '3') {
                    ui.info('Creating local repository in ~/.keys'.grey);
                    model.local = true;
                    model.settings.local = true;

                    let passwd_options = {
                        silent: true,
                        output: process.stderr
                    };

                    let passwd = await promptly.prompt('Create Password: ', passwd_options);
                    let confirm = await promptly.prompt('Confirm Password: ', passwd_options);

                    while (passwd !== confirm) {
                        ui.info('\nPasswords did not match\n');
                        passwd = await promptly.prompt('Create Password: ', passwd_options);
                        confirm = await promptly.prompt('Confirm Password: ', passwd_options);
                    }
                    model.creds.passwd = passwd;
                    let org_key = uuid();
                    let keypair = cryptico.generateRSAKey(passwd, 1024);
                    let public_key = cryptico.publicKeyString(keypair);
                    let hash = new SHA3(512);
                    hash.update(passwd);

                    model.user = {
                        email: null,
                        name: process.env.USER || process.env.LOGNAME || 'local_user',
                        passwd_hash: hash.digest('hex'),
                        org: '1',
                        id: '1',
                        org_keys_ct: {
                            '1': cryptico.encrypt(org_key, public_key).cipher
                        },
                        envs: {}
                    };
                    ui.info('Success'.green, 'Created local repository in ~/.keys'.grey);
                    return update_config(model).then(cache_model);

                } else if (answer === '2') {

                    ui.info('Creating new account...'.grey);

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
                        return request(options).then(() => {
                            ui.info('Created Account'.green, `at ${model.client.endpoint}`.grey);
                            model.settings.registered = true;
                            model.creds.email = email;
                            model.creds.passwd = passwd;
                            model.settings.email = model.creds.email;
                            return Promise.resolve(model);
                        }).catch((err) => {
                            ui.error(err);
                            return Promise.resolve(null);
                        });

                    } else {
                        ui.error('Passwords did not match');
                        return Promise.resolve(null);
                    }

                } else {
                    model.fresh = false;
                    ui.info('Log into existing account at https://keys.cm ...'.grey);
                }
            }

            if (!model.fresh && (!model.creds.email || !model.creds.passwd)) {

                if (!model.settings.local) {
                    let text = 'Email: ';
                    let email_options = {
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
                        model.creds.email = model.settings.email;
                    } else {
                        model.settings.email = model.creds.email;
                        let file = process.env.HOME + '/.keys/settings.json';
                        fs.writeFileSync(file, JSON.stringify(model.settings), {
                            encoding: 'utf-8'
                        });
                    }
                }
                let passwd_options = {
                    silent: true,
                    output: process.stderr
                };
                // TODO for import without stored passwd, promptly can't read stdin b/c already been processed
                model.creds.passwd = await promptly.prompt('Password: ', passwd_options);
            }
        }
    }

    return Promise.resolve(model);
};

let read_vars = (model, content) => {
    let env = {
        name: 'Unnamed',
        stage: 'dev',
        vars: {}
    };
    let lines = content.split(/\r?\n/);
    let vars = {};
    lines.forEach(line => {

        if (!line.match(/^\s?#/)) {
            let m = line.match(/(?<k>\w+)=(?<v>.+)/);
            if (m) {
                env.vars[m.groups.k] = {
                    value: m.groups.v,
                    updated: moment().unix(),
                    by: model.user.id
                };
            }
        } else {
            let m = line.match(/Environment Name: (?<name>.+)/);
            if(m){
                env.name = m.groups.name;
            }else{
                m = line.match(/Environment Stage: (?<stage>.+)/);
                if(m){
                    env.stage = m.groups.stage;
                }
            }
        }
    });
    return env;
}

let import_env = async (model) => {

    if (model && model.import) {
        let env = {};
        if (!model.env_name) {
            model.env_name = 'New-Environment-' + parseInt(Date.now() / 1000);
        }
        if (model.input) {
            env = read_vars(model, model.input);
        } else {

            let existing = '';
            if ( Object.keys(model.user.envs).length < 1 ){
                model.edit = false;
                model.selected = null;
            }
            if ( model.edit && !model.selected ){
                model.selected = await ui.choose(model.user.envs);
                model.env_name = model.user.envs[model.selected].name;
                let env = model.user.envs[model.selected];
                _.each(env.vars, (v,k) => {
                    existing += `${k}=${v.value}\n`;
                });
            }

            temp.track();
            let header = `# Environment Name: ${model.env_name}\n`;
            header += '# Environment Stage: dev\n';
            header += '# Enter environment variables below, one per line\n';
            header += '# NAME=VALUE\n';
            header += existing + '\n';

            let tmp = temp.path({suffix: '.env'});
            fs.writeFileSync(tmp, header);
            let args = '';
            let editor = process.env.EDITOR || 'vim';
            if (editor === 'vim' || editor === 'vi'){
                args = '+5';
            }
            child_process.execSync(
                `${editor} ${args} ${tmp}`,
                {stdio: 'inherit'}
            );
            let content = fs.readFileSync(tmp, 'utf8');
            if ( header === content ){
                 ui.info('WARN'.yellow, 'No changes were made.');
                 return Promise.resolve(null);
            }
            env = read_vars(model, content);
        }
        env.vars_ct = crypto.encrypt(model.user.org_keys[model.user.org], JSON.stringify(env.vars))
        if (!model.selected) {
            model.selected = uuid();
        }
        env.id = model.selected;

        if (model.settings.local) {
            model.user.envs[env.id] = env;
            model.user.envs[env.id].org = '1';
            let action = model.edit ? 'Updated' : 'Created';
            ui.info(action.green, env.name.bold, `with ${_.size(env.vars)} variables.`);
            return cache_model(model);
        } else {
            let options = {
                uri: model.client.endpoint + '/env/update',
                jar: true,
                json: env,
                method: 'POST'
            };
            return request(options).then(() => {
                let action = model.create_env ? 'Created' : 'Updated';
                ui.info(action.green, env.name.bold, `with ${_.size(env.vars)} variables.`);
                return Promise.resolve(null);
            }).catch((err) => {
                ui.error(err);
                return Promise.resolve(null);
            });
        }
    } else {
        return Promise.resolve(model);
    }
};

let update_stats = async (model) => {

    if (model && !model.local && !model.settings.local && model.selected && !model.creds.token && model.source === 'keys') {

        let body = {
            id: model.selected,
            accessed: moment().unix(),
            selected: true
        };

        let options = {
            uri: model.client.endpoint + '/env/update',
            jar: true,
            json: body,
            method: 'POST'
        };
        request(options).catch(err => ui.error(err));
    }

    return Promise.resolve(model);
};

let ask_env = async (model) => {

    if (model) {

        if (model.source !== 'keys') {
            model.user = {
                envs: await model.source.envs()
            };
            model.selected = await ui.choose(model.user.envs);
            return Promise.resolve(model);
        }

        if (Object.keys(model.user.envs).length < 1 && !model.import) {
            ui.info('No environments found, use -i or --import to add an environment to the repository');
            ui.info();
            ui.info('Examples:');
            ui.info('    keys -i');
            ui.info('    cat .env | keys -i');
            process.exit(0);
        }

        if (model.token) {
            model.selected = _.findKey(model.user.envs, () => true);
        } else if (model.env_name) {
            let found = _.find(model.user.envs, {
                name: model.env_name
            });
            if (found) {
                model.selected = found.id;
            } else {
                if (!model.import && !model.edit) {
                    ui.info('NotFound'.yellow, model.env_name);
                }
            }
        } else if (model.import) {
            if (model.import) {
                model.create_env = true;
            }
        }

        if (model.selected) {
            if (!model.import) {
                ui.info(`Loading environment: ${model.user.envs[model.selected].name}`);
            }
            return Promise.resolve(model);
        } else {
            if (!model.import) {
                model.selected = await ui.choose(model.user.envs);
                return Promise.resolve(model);
            } else {
                return Promise.resolve(model);
                // if (model.create_env) {
                //     return Promise.resolve(model);
                // } else {
                //     ui.info('Use', '-e name'.yellow, 'with', '-i'.yellow, 'to specify an environment to create/update');
                //     return Promise.resolve(null);
                // }
            }
        }
    }
};

let execute = (model) => {

    if (model && !model.import) {
        let env = {};
        let shell = false;

        if (!model.clean) {
            env = _.clone(process.env);
            shell = true;
        }

        _.each(model.user.envs[model.selected].vars, (v, k) => {
            env[k] = v.value;
        });

        if (_.trim(model.cmd).length < 1) {
            ui.info('');
            ui.info('Typical usage is:');
            ui.info('  keys [command you want to run with the environment variables loaded]');
            ui.info('');
            ui.info('No command was provided, exiting. ');
        } else {
            ui.info('Executing'.green, model.cmd);
            spawn(model.cmd, {
                stdio: 'inherit',
                shell: shell,
                env: env,
            });
        }
    }

    return Promise.resolve();
};

let login = async (model) => {

    if (model) {
        if (model.local || model.settings.local) {
            return load_cache(model);
        } else if (model.source === 'keys') {
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
            return request(options).then(async (body) => {

                model.settings.endpoint = model.client.endpoint;

                if (_.has(body, '2fa') && body['2fa']) {
                    let twofactor_options = {
                        output: process.stderr
                    };
                    let code = await promptly.prompt('2FA Code: ', twofactor_options);

                    req = {
                        user: body['user'],
                        code: code
                    };
                    return request.post(model.client.endpoint + '/totp/login', {
                        json: req
                    }).then((body) => {

                        ui.info('AuthSuccess'.green, `for ${model.creds.email}`.grey);
                        _.merge(model, body);
                        model.settings.registered = true;

                        store_creds(model.creds);
                        return Promise.resolve(model);

                    }).catch(err => {
                        console.error(err.message);
                        ui.die('AuthFailed', 'Invalid 2FA Code');
                    });

                } else {
                    let auth_for = model.creds.token ? 'token' : model.creds.email;
                    ui.info('AuthSuccess'.green, `for ${auth_for}`.grey);
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
                        ui.die('AuthFailed', 'Invalid Token');
                    } else {
                        ui.die('AuthFailed', 'Bad Username/Password');
                    }
                }
                ui.error('WARN'.yellow, `Failure to reach ${model.client.endpoint}, entering --local mode.`);
                model.local = true;
                return load_cache(model);
            });
        } else {
            return Promise.resolve(model);
        }
    } else {
        return Promise.resolve(model);
    }
};

let decrypt_model = (model) => {

    try {

        if (model && model.source === 'keys') {
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

            if (_.has(model.user, 'envs') && Object.keys(model.user.envs).length > 0) {
                _.each(model.user.envs, (env, id) => {
                    if (model.token && (!_.has(model, 'selected') || !model.selected)) {
                        model.selected = id;
                    }
                    if (env.vars_ct) {
                        model.user.envs[id].vars = JSON.parse(crypto.decrypt(model.user.org_keys[env.org], env.vars_ct));
                    }
                });
            }
        }

    }catch(e){
         ui.info('AuthFailure'.red, 'Invalid password');
         ui.info('Environment data cannot be decrypted without the password.'.grey);
         ui.info('To create a new repository, use --reset'.grey);
         return Promise.resolve(null);
    }

    return Promise.resolve(model);
};

let specials = async (model) => {

    if (model) {
        let parts = _.chain(model.cmd).toLower().words().value();
        let vars = model.user.envs[model.selected].vars;

        if (parts.length && parts[0] === 'docker') {
            _.each(vars, (val, key) => {
                model.cmd += ` -e ${key}`;
            });
        }

        // for liaisons to lazy-fetch the specific env once chosen
        if (model.source !== 'keys') {
            model.user.envs[model.selected].vars = await model.source.env(model.selected);
        }


        if (model.destination) {
            ui.info(`\nChoose the ${model.destination.get_name()} ${model.destination.get_env_name()} to push ${model.user.envs[model.selected].name} (${_.keys(model.user.envs[model.selected].vars).length} vars) to:`.green);
            let envs = await model.destination.envs(model);
            let dest = await ui.choose(envs, 'Choose Destination #: ');

            let message = 'Pushing ' + model.user.envs[model.selected].name.bold + ` to ${model.destination.get_name()} ${model.destination.get_env_name()} ` + dest.bold;
            const spinner = ora(message).start();
            // let spin = new spinner(`%s Pushing ` + model.user.envs[model.selected].name.bold + ` to ${model.destination.get_name()} ${model.destination.get_env_name()} ` + dest.bold);
            // spin.setSpinnerString(18);
            // spin.start();
            await model.destination.push(dest, model.user.envs[model.selected].vars, spinner);
            spinner.stop();
            ui.info('\nSuccess'.green, `Updated ${model.destination.get_name()} ${model.destination.get_env_name()} ${dest}`);
            process.exit(1);
        }
    }

    return Promise.resolve(model);
};

let main = async () => {

    model.spinner = ora('Initializing\n').start();

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
            ui.is_debug ? console.trace(e) : console.error(e.message.red);
        });
};

if (require.main === module) {
    main();
}

let cli = {
    default_settings: default_settings,
    model: model,
    load_config: load_config,
    handle_args: handle_args,
    self_update: self_update,
    capture_stdin: capture_stdin,
    print_intro: print_intro,
    load_creds: load_creds,
    ask_creds: ask_creds,
    host_info: host_info,
    login: login,
    update_config: update_config,
    decrypt_model: decrypt_model,
    ask_env: ask_env,
    update_stats: update_stats,
    import_env: import_env,
    specials: specials,
    execute: execute
};

module.exports = cli;