const colors = require('colors'); // eslint-disable-line no-unused-vars
const _ = require('lodash');
const promptly = require('promptly');
const columnify = require('columnify');

let ui = {

    is_debug: false,

    set_debug: (bool) => {
        ui.is_debug = bool;
    },

    error: (...messages) => {
        let line = '';
        _.each(messages, (m, i) => {
            line += i == 0 ? `${m} `.red : `${m} `;
        });
        console.error(line);
    },

    die: (...messages) => {
        ui.error(...messages);
        process.exit(1);
    },

    info: (...messages) => {
        let line = '';
        _.each(messages, (m) => {
            line += `${m} `;
        });
        console.error(line);
    },

    debug: (message) => {
        if (ui.is_debug) {
            console.error(message.grey);
        }
    },

    choose: async(envs_map, message) => {

        let envs_all = _.map(envs_map, (env) => {
            return env;
        });

        let envs = _.groupBy(envs_all, 'stage');

        let choices = {};
        let i = 1;
        _.each(envs, (v, k) => {
            choices[k] = i;
            i += v.length;
        });

        let env_choice = {};
        let rows = [];
        for (let i = 0; i < envs_all.length; i++) {
            let row = {}
            _.each(_.keys(choices), (stage) => {
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

        let columns = columnify(rows, {
            columnSplitter: '    '
        });
        ui.info(columns);
        ui.info();
        text = message ? message : 'Load Environment #: ';
        let env_index = await promptly.prompt(text, { output: process.stderr });
        if (env_index > 0 && _.keys(env_choice).length >= env_index) {
            return env_choice[env_index];
            // return Promise.resolve(model);
        } else {
            ui.error('Invalid Selection');
        }
    }
}

module.exports = ui;