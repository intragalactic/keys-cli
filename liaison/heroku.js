const _ = require('lodash');
const ui = require('../ui');
const {
    execSync
} = require('child_process');

const heroku = {

    get_name: () => {
        return 'heroku';
    },

    get_env_name: () => {
        return 'app';
    },

    envs: async(model) => {

        let envs = {};

        r_cat = /===\s+([0-9a-zA-Z_.\-@]+)/;
        r_app = /([0-9a-zA-Z_.\-@]+)/;

        try {
            let result = await execSync('heroku apps', { shell: true, stdio: ['pipe', 'pipe', 'ignore'] });
            result = result.toString();
            if (result.includes('Heroku credentials')) {
                ui.error('ERROR'.red, 'Log in to heroku CLI before running this again (run: heroku login)');
                process.exit(1);
            }
            let current_category = null;
            _.each(result.split('\n'), (line) => {
                let match = r_cat.exec(line);
                if (match) {
                    current_category = match[1].split(/\s/)[0];
                } else {
                    let match = r_app.exec(line);
                    if (match) {
                        let app = match[1];
                        let env = {
                            id: app,
                            name: app,
                            stage: current_category
                        }
                        envs[app] = env;
                    }
                }
            });
        } catch (error) {
            // console.log(error.status); // Might be 127 in your example.
            // ui.error('ERROR'.red, error.message);
            ui.error('ERROR'.red, 'Make sure you have the heroku CLI installed and are logged in (run: heroku login)')
            process.exit(error.status);
        }

        return envs;
    },

    env: async(envid) => {
        let result = await execSync(`heroku config -s -a ${envid}`, { shell: true });
        result = result.toString();
        let r_var = /(.+)=(.+)/;
        let vars = {};
        _.each(result.split('\n'), (line) => {
            let match = r_var.exec(line);
            if (match) {
                let key = match[1];
                let val = match[2];

                if ((val[0] == "'" || val[0] == '"') && (val[0] == "'" || val[0] == '"')) {
                    val = val.slice(1, -1);
                }
                vars[key] = {
                    value: val
                }
            }
        });
        return vars;
    },

    push: async(envid, vars, spinner) => {

        ui.debug('');
        _.each(vars, async(v, k) => {
            if (spinner && !ui.is_debug) {
                spinner.render();
            }
            let result = execSync(`heroku config:set -a ${envid} ${k}='${v.value}'`, { shell: true, stdio: ['pipe', 'pipe', 'ignore'] });
            result = result.toString();
            ui.debug(`Set ${k}`);
        });

        return true;
    }
}

module.exports = heroku;