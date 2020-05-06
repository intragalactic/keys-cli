const _ = require('lodash');
const ui = require('../ui');
const {
    execSync
} = require('child_process');
const progressbar = require('cli-progress');

const liaison = {

    endpoint: null,

    get_name: () => {
        return 'pivotal';
    },

    get_env_name: () => {
        return 'app';
    },

    envs: async(model) => {

        if (liaison.endpoint) {
            let name = liaison.get_name();
            ui.info('WARN'.yellow, `Ignoring --endpoint ${liaison.endpoint} for --source ${name}`);
            ui.info('WARN'.yellow, 'To change pivotal cf endpoint, run', 'cf login -a [endpoint]'.blue);
        }

        let envs = {};

        r_cat = /Getting apps in org ([0-9a-zA-Z_.\-@]+) \/ space ([0-9a-zA-Z_.\-@]+)/;
        r_app = /([0-9a-zA-Z_.\-@]+)\s+(.+)\s+(.+)\s+(.+)\s(.*)/;

        let header = false;

        try {
            let result = await execSync('cf apps', { shell: true, stdio: ['pipe', 'pipe', 'ignore'] });
            result = result.toString();
            if (result.includes('FAILED')) {
                ui.error('ERROR'.red, 'Install and log in to pivotal CLI before running this again (run: cf login)');
                process.exit(1);
            }
            let current_category = null;
            _.each(result.split('\n'), (line) => {
                let match = r_cat.exec(line);
                if (match) {
                    current_category = `${match[1]}/${match[2]}`;
                } else {
                    let match = r_app.exec(line);
                    if (match) {
                        if (header) {
                            let app = match[1];
                            let env = {
                                id: app,
                                name: app,
                                stage: current_category
                            }
                            envs[app] = env;
                        } else {
                            header = true;
                        }
                    }
                }
            });
        } catch (error) {
            ui.error('ERROR'.red, 'Install and log in to pivotal CLI before running this again (run: cf login)');
            process.exit(error.status);
        }

        return envs;
    },

    env: async(envid) => {
        let result = await execSync(`cf env ${envid}`, { shell: true });
        result = result.toString();
        let r_var = /(.+):\s+(.+)/;
        let r_user_provided = /User-Provided:/
        let vars = {};
        in_user_provided = false;
        _.each(result.split('\n'), (line) => {

            if (!in_user_provided) {
                let match = r_user_provided.exec(line);
                if (match) {
                    in_user_provided = true;
                }
            } else {
                if (line.trim().length > 1) {
                    let match = r_var.exec(line);
                    if (match) {
                        let key = match[1];
                        let val = match[2];

                        vars[key] = {
                            value: val
                        }
                    }
                } else {
                    in_user_provided = false;
                }
            }
        });
        return vars;
    },

    push: async(envid, vars, spinner) => {

        ui.debug('');

        const progress = new progressbar.SingleBar({ stream: process.stderr, }, progressbar.Presets.rect);
        progress.start(_.keys(vars).length, 0);

        _.each(vars, async(v, k) => {

            let result = execSync(`cf set-env ${envid} ${k} '${v.value}'`, { shell: true, stdio: ['pipe', 'pipe', 'ignore'] });
            result = result.toString();
            progress.increment();
            ui.debug(` Set ${k}`);
        });

        progress.stop();

        return true;
    }
}

module.exports = liaison;